"""Deterministic rules for normalized Kubernetes NetworkPolicy evidence.

The engine evaluates only the isolation state established by the collector. It
does not use AI, inspect policy allow rules, contact a cluster, or infer that a
selected policy is restrictive.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from src.collectors.network_policy import EVIDENCE_SOURCE
from src.models import Evidence, ScanResult, ScanStatus

DEFAULT_RISK_RULES_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "risk-rules.yaml"
)

_REQUIRED_WEIGHTS = {
    "missing_network_policy",
    "missing_ingress_isolation",
    "missing_egress_isolation",
}
_RUNTIME_LIMITATION = (
    "Runtime CNI enforcement was not verified. Declared isolation does not prove "
    "that a matching policy is restrictive; its traffic rules were not analyzed."
)


def deterministic_network_policy_finding_id(
    *, cluster: str, namespace: str, kind: str, workload: str, rule_id: str
) -> str:
    """Return a stable hexadecimal ID for one workload and rule."""

    identity = json.dumps(
        [cluster, namespace, kind, workload, rule_id],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"KSA-{hashlib.sha256(identity).hexdigest()[:12]}"


def _load_config(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as config_file:
            config = yaml.safe_load(config_file)
    except OSError as exc:
        raise ValueError(f"unable to read risk rules config: {path}") from exc
    if not isinstance(config, dict):
        raise ValueError("risk rules config must be an object")
    return config


def _integer_mapping(config: Mapping[str, Any], key: str) -> dict[str, int]:
    value = config.get(key)
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"risk rules config requires a non-empty {key} mapping")
    if not all(
        isinstance(name, str)
        and isinstance(number, int)
        and not isinstance(number, bool)
        for name, number in value.items()
    ):
        raise ValueError(f"risk rules config {key} values must be integers")
    return dict(value)


def _target_from_mapping(
    workload: Mapping[str, Any],
) -> dict[str, str | None] | None:
    target: dict[str, str | None] = {
        "cluster": workload.get("cluster"),
        "namespace": workload.get("namespace"),
        "kind": workload.get("kind"),
        "name": workload.get("name"),
        "container": None,
    }
    if not all(
        isinstance(value, str) and value.strip()
        for key, value in target.items()
        if key != "container"
    ):
        return None
    return target


def _target_key(target: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(target["cluster"]),
        str(target["namespace"]),
        str(target["kind"]),
        str(target["name"]),
    )


def _canonical_evidence(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate exact observations without discarding policy details."""

    unique = {
        json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")): item
        for item in items
    }
    return [deepcopy(unique[key]) for key in sorted(unique)]


def _evidence_dict(item: Evidence | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(item, Evidence):
        return item.to_dict()
    if isinstance(item, Mapping):
        return deepcopy(dict(item))
    raise TypeError("evidence must contain Evidence objects or mappings")


def _scan_failure_evidence(scan: ScanResult) -> dict[str, Any]:
    """Represent an evidence-less collector failure without inventing policy facts."""

    return {
        "source": f"{EVIDENCE_SOURCE}.collection_status",
        # ScanResult does not carry a collection timestamp. This explicit sentinel
        # keeps failure output deterministic and makes the missing observation clear.
        "observed_at": "1970-01-01T00:00:00Z",
        "collector_version": "unavailable",
        "details": {
            "workload": scan.target.to_dict(),
            "collection_status": scan.status.value,
            "errors": scan.errors.copy(),
            "observation_available": False,
        },
    }


class NetworkPolicyRuleEngine:
    """Convert NetworkPolicy isolation evidence into one result per workload."""

    def __init__(self, *, config_path: str | Path | None = None) -> None:
        self.config_path = Path(config_path or DEFAULT_RISK_RULES_PATH)
        config = _load_config(self.config_path)
        self.weights = _integer_mapping(config, "weights")
        self.severity_thresholds = _integer_mapping(config, "severity_thresholds")

        limits = _integer_mapping(config, "score_limits")
        self.minimum_score = limits.get("minimum", 0)
        self.maximum_score = min(limits.get("maximum", 100), 100)
        if self.minimum_score < 0 or self.minimum_score > self.maximum_score:
            raise ValueError("score_limits must define 0 <= minimum <= maximum <= 100")

        missing_weights = sorted(_REQUIRED_WEIGHTS.difference(self.weights))
        if missing_weights:
            raise ValueError(
                "risk rules config is missing weights: " + ", ".join(missing_weights)
            )

    def analyze(
        self,
        evidence: Iterable[Evidence | Mapping[str, Any] | ScanResult] | ScanResult,
    ) -> list[dict[str, Any]]:
        """Return at most one deterministic NetworkPolicy result per workload."""

        raw_items: Iterable[Evidence | Mapping[str, Any] | ScanResult]
        if isinstance(evidence, ScanResult):
            raw_items = [evidence]
        elif isinstance(evidence, Mapping) and self._is_scan_result_mapping(evidence):
            raw_items = [evidence]
        elif isinstance(evidence, (Evidence, Mapping)):
            raise TypeError("evidence must be an iterable of evidence items")
        else:
            raw_items = evidence

        groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for raw_item in raw_items:
            if isinstance(raw_item, ScanResult):
                self._add_scan_result(groups, raw_item)
            elif isinstance(raw_item, Mapping) and self._is_scan_result_mapping(
                raw_item
            ):
                self._add_scan_result(groups, ScanResult.from_dict(raw_item))
            else:
                self._add_evidence(groups, _evidence_dict(raw_item))

        results = [
            result
            for group in groups.values()
            if (result := self._result(group)) is not None
        ]
        return sorted(
            results,
            key=lambda result: (
                result["target"]["cluster"],
                result["target"]["namespace"],
                result["target"]["kind"],
                result["target"]["name"],
                result["finding_id"],
            ),
        )

    evaluate = analyze

    @staticmethod
    def _is_scan_result_mapping(value: Mapping[str, Any]) -> bool:
        return {"target", "status", "evidence"}.issubset(value)

    def _group(
        self,
        groups: dict[tuple[str, str, str, str], dict[str, Any]],
        target: dict[str, str | None],
    ) -> dict[str, Any]:
        return groups.setdefault(
            _target_key(target),
            {"target": target, "states": set(), "unknown": False, "evidence": []},
        )

    def _add_scan_result(
        self,
        groups: dict[tuple[str, str, str, str], dict[str, Any]],
        scan: ScanResult,
    ) -> None:
        target = scan.target.to_dict()
        group = self._group(groups, target)
        matching_evidence = [
            item.to_dict() for item in scan.evidence if item.source == EVIDENCE_SOURCE
        ]
        for item in matching_evidence:
            self._add_evidence(groups, item)

        if scan.status is not ScanStatus.COMPLETE or not matching_evidence:
            group["unknown"] = True
            if not matching_evidence:
                group["evidence"].append(_scan_failure_evidence(scan))

    def _add_evidence(
        self,
        groups: dict[tuple[str, str, str, str], dict[str, Any]],
        item: dict[str, Any],
    ) -> None:
        if item.get("source") != EVIDENCE_SOURCE:
            return
        details = item.get("details")
        if not isinstance(details, Mapping):
            return
        workload = details.get("workload")
        if not isinstance(workload, Mapping):
            return
        target = _target_from_mapping(workload)
        if target is None:
            return

        group = self._group(groups, target)
        group["evidence"].append(item)

        collection_status = details.get("collection_status")
        if collection_status in {
            ScanStatus.PARTIAL.value,
            ScanStatus.INSUFFICIENT_EVIDENCE.value,
            ScanStatus.COLLECTION_FAILED.value,
        }:
            group["unknown"] = True
            return

        ingress = details.get("ingress_isolated")
        egress = details.get("egress_isolated")
        if not isinstance(ingress, bool) or not isinstance(egress, bool):
            group["unknown"] = True
            return

        matching = self._matching_policy_state(details)
        if matching is False and (ingress or egress):
            group["unknown"] = True
            return
        if not ingress and not egress and matching is not False:
            # Both directions being open is only the no-policy rule when the
            # collector affirmatively observed that no policy selected the pod.
            group["unknown"] = True
            return
        group["states"].add((ingress, egress))

    @staticmethod
    def _matching_policy_state(details: Mapping[str, Any]) -> bool | None:
        observed: list[bool] = []
        for field in ("matching_policies", "policies"):
            value = details.get(field)
            if isinstance(value, list):
                observed.append(bool(value))
            elif value is not None:
                return None
        if not observed or len(set(observed)) != 1:
            return None
        return observed[0]

    def _result(self, group: Mapping[str, Any]) -> dict[str, Any] | None:
        target = deepcopy(group["target"])
        evidence = _canonical_evidence(group["evidence"])
        states = group["states"]
        if group["unknown"] or len(states) != 1:
            return self._insufficient_evidence(target=target, evidence=evidence)

        ingress, egress = next(iter(states))
        if ingress and egress:
            return None
        if not ingress and not egress:
            return self._finding(
                target=target,
                evidence=evidence,
                risk_factor="missing_network_policy",
                title="Workload has no matching NetworkPolicy",
                recommendation=(
                    "Add NetworkPolicies that select this workload and define its "
                    "required ingress and egress traffic."
                ),
            )
        if ingress:
            return self._finding(
                target=target,
                evidence=evidence,
                risk_factor="missing_egress_isolation",
                title="Workload is not isolated for egress",
                recommendation=(
                    "Add egress isolation for this workload after documenting its "
                    "required outbound traffic."
                ),
            )
        return self._finding(
            target=target,
            evidence=evidence,
            risk_factor="missing_ingress_isolation",
            title="Workload is not isolated for ingress",
            recommendation=(
                "Add ingress isolation for this workload after documenting its "
                "required inbound traffic."
            ),
        )

    def _finding(
        self,
        *,
        target: dict[str, str | None],
        evidence: list[dict[str, Any]],
        risk_factor: str,
        title: str,
        recommendation: str,
    ) -> dict[str, Any]:
        score = max(
            self.minimum_score,
            min(self.weights[risk_factor], self.maximum_score, 100),
        )
        return {
            "finding_id": self._finding_id(target, risk_factor),
            "title": title,
            "status": "CONFIRMED",
            "severity": self._severity(score),
            "score": score,
            "confidence": "high",
            "target": target,
            "evidence": evidence,
            "risk_factors": [risk_factor],
            "attack_path": None,
            "blast_radius": None,
            "recommendations": [recommendation],
            "limitations": [_RUNTIME_LIMITATION],
        }

    def _insufficient_evidence(
        self,
        *,
        target: dict[str, str | None],
        evidence: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "finding_id": self._finding_id(target, "insufficient_evidence"),
            "title": "Workload NetworkPolicy isolation could not be determined",
            "status": "INSUFFICIENT_EVIDENCE",
            "severity": self._severity(0),
            "score": 0,
            "confidence": "low",
            "target": target,
            "evidence": evidence,
            "risk_factors": [],
            "attack_path": None,
            "blast_radius": None,
            "recommendations": [
                "Collect complete matching NetworkPolicy evidence before assessing "
                "workload isolation."
            ],
            "limitations": [
                _RUNTIME_LIMITATION,
                "Evidence was missing, invalid, contradictory, or collection failed.",
            ],
        }

    @staticmethod
    def _finding_id(target: Mapping[str, Any], rule_id: str) -> str:
        return deterministic_network_policy_finding_id(
            cluster=str(target["cluster"]),
            namespace=str(target["namespace"]),
            kind=str(target["kind"]),
            workload=str(target["name"]),
            rule_id=rule_id,
        )

    def _severity(self, score: int) -> str:
        matching = [
            (threshold, severity)
            for severity, threshold in self.severity_thresholds.items()
            if score >= threshold
        ]
        if not matching:
            return "info"
        return max(matching, key=lambda item: item[0])[1]


def analyze_network_policy(
    evidence: Iterable[Evidence | Mapping[str, Any] | ScanResult] | ScanResult,
    *,
    config_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Convenience wrapper for :class:`NetworkPolicyRuleEngine`."""

    return NetworkPolicyRuleEngine(config_path=config_path).analyze(evidence)


evaluate_network_policy = analyze_network_policy
