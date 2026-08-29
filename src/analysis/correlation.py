"""Pure, deterministic correlation of confirmed findings into plausible paths.

This module performs no inference, model call, cluster access, or other I/O beyond
loading the versioned risk configuration and output schema at engine creation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from src.models.attack_path import AttackPath


DEFAULT_RISK_RULES_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "risk-rules.yaml"
)
DEFAULT_ATTACK_PATH_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "schemas" / "attack-path.schema.json"
)

_FINDING_ID = re.compile(r"^KSA-[0-9a-fA-F]{12}$")
_WORKLOAD_FIELDS = ("cluster", "namespace", "kind", "name")
_BASE_LIMITATION = (
    "This path is plausible from configuration and scanner findings; it does not "
    "establish access, execution, compromise, or exploitation."
)
_PARTIAL_LIMITATION = (
    "The scan was partial; unavailable evidence may change this attack-path "
    "assessment."
)
_POTENTIAL_EXPOSURE_LIMITATION = (
    "The exposure signal is potentially external; public reachability was not "
    "confirmed."
)


@dataclass(frozen=True, slots=True)
class _CorrelationRule:
    rule_id: str
    required_groups: tuple[tuple[str, ...], ...]
    title: str
    explanation: str


_RULES = (
    _CorrelationRule(
        rule_id="external_high_impact_cve",
        required_groups=(
            ("public_exposure", "potential_external_exposure"),
            ("critical_cve", "high_cve"),
        ),
        title="External exposure combines with a high-impact image vulnerability",
        explanation=(
            "Confirmed findings identify an external-exposure risk and a critical "
            "or high image vulnerability on the same workload. This combination "
            "is a plausible entry path if the affected code is reachable."
        ),
    ),
    _CorrelationRule(
        rule_id="external_privileged_or_root",
        required_groups=(
            ("public_exposure", "potential_external_exposure"),
            ("privileged_container", "runs_as_root"),
        ),
        title="External exposure combines with privileged or root execution",
        explanation=(
            "Confirmed findings identify an external-exposure risk and a container "
            "that is privileged or runs as root on the same workload. This "
            "combination could increase impact if another weakness permits access."
        ),
    ),
    _CorrelationRule(
        rule_id="privileged_excessive_rbac",
        required_groups=(
            ("privileged_container",),
            (
                "cluster_admin_binding",
                "namespace_admin_permission",
                "rbac_escalation_permission",
            ),
        ),
        title="Privileged execution combines with excessive RBAC permissions",
        explanation=(
            "Confirmed findings identify a privileged container and excessive RBAC "
            "permissions for the same workload. The permissions could broaden impact "
            "if the workload were compromised."
        ),
    ),
    _CorrelationRule(
        rule_id="secret_access_pod_execution",
        required_groups=(("secrets_read_permission",), ("pod_exec_permission",)),
        title="Secret access combines with pod execution permissions",
        explanation=(
            "Confirmed findings identify both Secret-read and pod-exec permissions "
            "for the same workload identity. Together they form a plausible path to "
            "access sensitive data or other running containers if credentials are "
            "misused."
        ),
    ),
    _CorrelationRule(
        rule_id="external_missing_network_policy",
        required_groups=(
            ("public_exposure", "potential_external_exposure"),
            ("missing_network_policy",),
        ),
        title="External exposure combines with missing network isolation",
        explanation=(
            "Confirmed findings identify an external-exposure risk and no matching "
            "NetworkPolicy for the same workload. The missing isolation could permit "
            "broader network reachability if the workload were compromised."
        ),
    ),
)

_REQUIRED_WEIGHT_KEYS = frozenset(
    factor
    for rule in _RULES
    for group in rule.required_groups
    for factor in group
)


def deterministic_attack_path_id(
    *,
    rule_id: str,
    target: Mapping[str, Any],
    supporting_finding_ids: Iterable[str],
    risk_factors: Iterable[str],
) -> str:
    """Return a stable ID for one rule, workload, and supporting evidence set."""

    identity = {
        "rule_id": rule_id,
        "target": [target[field] for field in _WORKLOAD_FIELDS],
        "supporting_finding_ids": sorted(set(supporting_finding_ids)),
        "risk_factors": sorted(set(risk_factors)),
    }
    canonical = json.dumps(
        identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f"KAP-{hashlib.sha256(canonical).hexdigest()[:12]}"


def _load_mapping(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as source:
            value = yaml.safe_load(source)
    except OSError as exc:
        raise ValueError(f"unable to read risk rules config: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError("risk rules config must be an object")
    return value


def _weights(config: Mapping[str, Any]) -> dict[str, int]:
    value = config.get("weights")
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str)
        and isinstance(weight, int)
        and not isinstance(weight, bool)
        and weight >= 0
        for key, weight in value.items()
    ):
        raise ValueError("risk rules config weights must be non-negative integers")
    missing = sorted(_REQUIRED_WEIGHT_KEYS.difference(value))
    if missing:
        raise ValueError("risk rules config is missing weights: " + ", ".join(missing))
    return dict(value)


def _workload_key(finding: Mapping[str, Any]) -> tuple[str, str, str, str] | None:
    target = finding.get("target")
    if not isinstance(target, Mapping):
        return None
    values = tuple(target.get(field) for field in _WORKLOAD_FIELDS)
    if not all(isinstance(value, str) and value.strip() for value in values):
        return None
    return values  # type: ignore[return-value]


def _normalized_finding(
    finding: Any,
) -> tuple[tuple[str, str, str, str], str, tuple[str, ...]] | None:
    """Fail closed for malformed, ambiguous, or unconfirmed input."""

    if not isinstance(finding, Mapping) or finding.get("status") != "CONFIRMED":
        return None
    finding_id = finding.get("finding_id")
    factors = finding.get("risk_factors")
    workload = _workload_key(finding)
    if (
        workload is None
        or not isinstance(finding_id, str)
        or _FINDING_ID.fullmatch(finding_id) is None
        or not isinstance(factors, list)
        or not all(isinstance(factor, str) and factor.strip() for factor in factors)
    ):
        return None
    return workload, finding_id, tuple(sorted(set(factors)))


def _gap_limitations(evidence_gaps: Iterable[Any]) -> list[str]:
    normalized: set[tuple[str, str, str]] = set()
    for gap in evidence_gaps:
        if not isinstance(gap, Mapping):
            continue
        component = gap.get("component")
        stage = gap.get("stage")
        status = gap.get("status")
        if all(isinstance(value, str) and value.strip() for value in (component, stage, status)):
            normalized.add((component, stage, status))
    return [
        f"Evidence gap: {component} {stage.lower()} status is {status}."
        for component, stage, status in sorted(normalized)
    ]


class CorrelationEngine:
    """Apply fixed multi-signal rules to confirmed findings only."""

    def __init__(
        self,
        *,
        config_path: str | Path | None = None,
        schema_path: str | Path | None = None,
    ) -> None:
        self.config_path = Path(config_path or DEFAULT_RISK_RULES_PATH)
        self.weights = _weights(_load_mapping(self.config_path))
        self.schema_path = Path(schema_path or DEFAULT_ATTACK_PATH_SCHEMA_PATH)
        try:
            with self.schema_path.open(encoding="utf-8") as source:
                schema = json.load(source)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"unable to read attack-path schema: {self.schema_path}"
            ) from exc
        Draft202012Validator.check_schema(schema)
        self._validator = Draft202012Validator(schema)

    def correlate(
        self,
        findings_or_report: Iterable[Mapping[str, Any]] | Mapping[str, Any],
        *,
        scan_status: str | None = None,
        evidence_gaps: Iterable[Mapping[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Return deterministic plausible paths, grouped by workload.

        A full scan report can be passed directly. For a bare findings iterable,
        callers may supply ``scan_status`` and ``evidence_gaps`` explicitly.
        """

        if isinstance(findings_or_report, Mapping):
            if "findings" not in findings_or_report:
                raise TypeError("mapping input must be a scan report with findings")
            findings = findings_or_report.get("findings")
            if scan_status is None:
                scan_status = findings_or_report.get("scan_status")
            if evidence_gaps is None:
                evidence_gaps = findings_or_report.get("evidence_gaps", [])
        else:
            findings = findings_or_report

        if isinstance(findings, (str, bytes, Mapping)) or not isinstance(
            findings, Iterable
        ):
            raise TypeError("findings must be an iterable of finding mappings")
        if scan_status is None:
            scan_status = "COMPLETE"
        if scan_status not in {"COMPLETE", "PARTIAL"}:
            raise ValueError("scan_status must be COMPLETE or PARTIAL")
        if evidence_gaps is None:
            evidence_gaps = []
        if isinstance(evidence_gaps, (str, bytes, Mapping)) or not isinstance(
            evidence_gaps, Iterable
        ):
            raise TypeError("evidence_gaps must be an iterable of mappings")

        grouped: dict[
            tuple[str, str, str, str], dict[str, set[str]]
        ] = defaultdict(lambda: defaultdict(set))
        for raw_finding in findings:
            normalized = _normalized_finding(raw_finding)
            if normalized is None:
                continue
            workload, finding_id, factors = normalized
            for factor in factors:
                grouped[workload][factor].add(finding_id)

        limitations = [_BASE_LIMITATION]
        if scan_status == "PARTIAL":
            limitations.append(_PARTIAL_LIMITATION)
            limitations.extend(_gap_limitations(evidence_gaps))

        paths: list[tuple[tuple[str, str, str, str], int, dict[str, Any]]] = []
        for workload in sorted(grouped):
            factor_ids = grouped[workload]
            target = dict(zip(_WORKLOAD_FIELDS, workload, strict=True))
            for rule_index, rule in enumerate(_RULES):
                if not all(
                    any(factor in factor_ids for factor in group)
                    for group in rule.required_groups
                ):
                    continue

                matched_factors = sorted(
                    {
                        factor
                        for group in rule.required_groups
                        for factor in group
                        if factor in factor_ids
                    }
                )
                # This explicit guard keeps future rule edits fail-closed.
                if len(matched_factors) < 2:
                    continue
                supporting_ids = sorted(
                    {
                        finding_id
                        for factor in matched_factors
                        for finding_id in factor_ids[factor]
                    }
                )
                score = min(
                    100, sum(self.weights[factor] for factor in matched_factors)
                )
                explanation = rule.explanation
                path_limitations = limitations.copy()
                if (
                    "potential_external_exposure" in matched_factors
                    and "public_exposure" not in matched_factors
                ):
                    explanation = " ".join(
                        [explanation, _POTENTIAL_EXPOSURE_LIMITATION]
                    )
                    path_limitations.append(_POTENTIAL_EXPOSURE_LIMITATION)
                path = AttackPath(
                    attack_path_id=deterministic_attack_path_id(
                        rule_id=rule.rule_id,
                        target=target,
                        supporting_finding_ids=supporting_ids,
                        risk_factors=matched_factors,
                    ),
                    status="PLAUSIBLE",
                    title=rule.title,
                    score=score,
                    severity="high",
                    supporting_finding_ids=supporting_ids,
                    risk_factors=matched_factors,
                    explanation=explanation,
                    limitations=path_limitations,
                ).to_dict()
                self._validator.validate(path)
                paths.append((workload, rule_index, path))

        paths.sort(key=lambda item: (item[0], item[1], item[2]["attack_path_id"]))
        return [path for _, _, path in paths]

    analyze = correlate


def correlate_findings(
    findings_or_report: Iterable[Mapping[str, Any]] | Mapping[str, Any],
    *,
    scan_status: str | None = None,
    evidence_gaps: Iterable[Mapping[str, Any]] | None = None,
    config_path: str | Path | None = None,
    schema_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Functional entry point for deterministic correlation."""

    return CorrelationEngine(
        config_path=config_path, schema_path=schema_path
    ).correlate(
        findings_or_report,
        scan_status=scan_status,
        evidence_gaps=evidence_gaps,
    )


# Alternate verb used by the other deterministic analyzers.
analyze_correlation = correlate_findings


__all__ = [
    "CorrelationEngine",
    "DEFAULT_ATTACK_PATH_SCHEMA_PATH",
    "DEFAULT_RISK_RULES_PATH",
    "analyze_correlation",
    "correlate_findings",
    "deterministic_attack_path_id",
]
