"""Deterministic rules for Kubernetes SecurityContext evidence.

This module deliberately contains no model or network integration.  Every
finding is derived from one normalized evidence item and carries an unchanged
copy of that item so the result remains auditable.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import yaml

from src.collectors.security_context import EVIDENCE_SOURCE
from src.models import Evidence

DEFAULT_RISK_RULES_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "risk-rules.yaml"
)

# NET_BIND_SERVICE is the only capability that the Kubernetes Restricted Pod
# Security Standard permits a container to add.  Treat every other added
# capability as dangerous rather than maintaining an incomplete deny-list.
SAFE_ADDED_CAPABILITIES = frozenset({"NET_BIND_SERVICE"})


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    weight_key: str
    title: str
    matches: Callable[[Mapping[str, Any]], bool]
    recommendation: str


def _is_true(value: Any) -> bool:
    """Match an explicit boolean true, never truthy or unknown values."""

    return value is True


def _is_false(value: Any) -> bool:
    """Match an explicit boolean false, never falsey or unknown values."""

    return value is False


def _runs_as_uid_zero(value: Any) -> bool:
    # bool is an int subclass, so exclude it from the UID comparison.
    return isinstance(value, int) and not isinstance(value, bool) and value == 0


def _dangerous_added_capabilities(details: Mapping[str, Any]) -> tuple[str, ...]:
    capabilities = details.get("capabilities")
    if not isinstance(capabilities, Mapping):
        return ()

    added = capabilities.get("add")
    if not isinstance(added, list):
        return ()

    dangerous = {
        capability.strip().upper()
        for capability in added
        if isinstance(capability, str)
        and capability.strip()
        and capability.strip().upper() not in SAFE_ADDED_CAPABILITIES
    }
    return tuple(sorted(dangerous))


def _has_dangerous_added_capabilities(details: Mapping[str, Any]) -> bool:
    return bool(_dangerous_added_capabilities(details))


def _has_missing_seccomp_profile(details: Mapping[str, Any]) -> bool:
    """Confirm an explicitly empty, incomplete, or unconfined profile.

    A ``None`` value means the collector could not establish a configured
    value, so it is intentionally not promoted to a confirmed violation.
    """

    profile = details.get("seccompProfile")
    if not isinstance(profile, Mapping):
        return False
    profile_type = profile.get("type")
    return not profile_type or profile_type == "Unconfined"


def _uses_host_namespace(details: Mapping[str, Any]) -> bool:
    return any(
        details.get(field) is True for field in ("hostNetwork", "hostPID", "hostIPC")
    )


_RULES: tuple[_Rule, ...] = (
    _Rule(
        rule_id="privileged_true",
        weight_key="privileged_container",
        title="Container runs in privileged mode",
        matches=lambda details: _is_true(details.get("privileged")),
        recommendation="Set securityContext.privileged to false.",
    ),
    _Rule(
        rule_id="run_as_non_root_false",
        weight_key="runs_as_root",
        title="Container explicitly permits root execution",
        matches=lambda details: _is_false(details.get("runAsNonRoot")),
        recommendation="Set securityContext.runAsNonRoot to true.",
    ),
    _Rule(
        rule_id="run_as_user_zero",
        weight_key="runs_as_root",
        title="Container is configured to run as UID 0",
        matches=lambda details: _runs_as_uid_zero(details.get("runAsUser")),
        recommendation="Set securityContext.runAsUser to a non-zero UID.",
    ),
    _Rule(
        rule_id="allow_privilege_escalation_true",
        weight_key="allow_privilege_escalation",
        title="Container allows privilege escalation",
        matches=lambda details: _is_true(
            details.get("allowPrivilegeEscalation")
        ),
        recommendation="Set securityContext.allowPrivilegeEscalation to false.",
    ),
    _Rule(
        rule_id="dangerous_added_capabilities",
        weight_key="dangerous_capability",
        title="Container adds dangerous Linux capabilities",
        matches=_has_dangerous_added_capabilities,
        recommendation=(
            "Remove added Linux capabilities and drop ALL capabilities unless a "
            "specific capability is required."
        ),
    ),
    _Rule(
        rule_id="missing_seccomp_profile",
        weight_key="missing_seccomp_profile",
        title="Container has no confining seccomp profile",
        matches=_has_missing_seccomp_profile,
        recommendation="Set seccompProfile.type to RuntimeDefault or Localhost.",
    ),
    _Rule(
        rule_id="host_namespace_enabled",
        weight_key="host_namespace_access",
        title="Workload shares one or more host namespaces",
        matches=_uses_host_namespace,
        recommendation="Disable hostNetwork, hostPID, and hostIPC unless required.",
    ),
)


def deterministic_finding_id(
    *, namespace: str, workload: str, container: str, rule_id: str
) -> str:
    """Return the stable ID for a target/rule combination."""

    identity = json.dumps(
        [namespace, workload, container, rule_id],
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


def _evidence_dict(item: Evidence | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(item, Evidence):
        return item.to_dict()
    if isinstance(item, Mapping):
        return deepcopy(dict(item))
    raise TypeError("evidence must contain Evidence objects or mappings")


class SecurityContextRuleEngine:
    """Convert normalized SecurityContext evidence into confirmed findings."""

    def __init__(self, *, config_path: str | Path | None = None) -> None:
        self.config_path = Path(config_path or DEFAULT_RISK_RULES_PATH)
        config = _load_config(self.config_path)
        self.weights = _integer_mapping(config, "weights")
        self.severity_thresholds = _integer_mapping(config, "severity_thresholds")

        limits = _integer_mapping(config, "score_limits")
        self.minimum_score = limits.get("minimum", 0)
        # The product-level contract caps findings at 100 even if a config is
        # accidentally relaxed beyond that value.
        self.maximum_score = min(limits.get("maximum", 100), 100)
        if self.minimum_score < 0 or self.minimum_score > self.maximum_score:
            raise ValueError("score_limits must define 0 <= minimum <= maximum <= 100")

        missing_weights = sorted(
            {rule.weight_key for rule in _RULES}.difference(self.weights)
        )
        if missing_weights:
            raise ValueError(
                "risk rules config is missing weights: " + ", ".join(missing_weights)
            )

    def analyze(
        self, evidence: Iterable[Evidence | Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        """Return deterministic confirmed findings for the supplied evidence."""

        if isinstance(evidence, (Evidence, Mapping)):
            raise TypeError("evidence must be an iterable of evidence items")

        findings: list[dict[str, Any]] = []
        for raw_item in evidence:
            item = _evidence_dict(raw_item)
            if item.get("source") != EVIDENCE_SOURCE:
                continue
            details = item.get("details")
            if not isinstance(details, Mapping):
                continue

            target = self._target(details)
            if target is None:
                continue

            for rule in _RULES:
                if rule.matches(details):
                    findings.append(self._finding(rule, target, item))

        return sorted(
            findings,
            key=lambda finding: (
                finding["target"]["namespace"],
                finding["target"]["name"],
                finding["target"]["container"] or "",
                finding["finding_id"],
            ),
        )

    # ``evaluate`` is a natural rule-engine spelling and keeps call sites
    # readable while using the same implementation.
    evaluate = analyze

    def _target(self, details: Mapping[str, Any]) -> dict[str, str | None] | None:
        workload = details.get("workload")
        container = details.get("container")
        if not isinstance(workload, Mapping) or not isinstance(container, Mapping):
            return None

        values = {
            "cluster": workload.get("cluster"),
            "namespace": workload.get("namespace"),
            "kind": workload.get("kind"),
            "name": workload.get("name"),
            "container": container.get("name"),
        }
        if not all(
            isinstance(value, str) and value.strip() for value in values.values()
        ):
            return None
        return values

    def _finding(
        self,
        rule: _Rule,
        target: dict[str, str | None],
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        score = max(
            self.minimum_score,
            min(self.weights[rule.weight_key], self.maximum_score, 100),
        )
        return {
            "finding_id": deterministic_finding_id(
                namespace=str(target["namespace"]),
                workload=str(target["name"]),
                container=str(target["container"]),
                rule_id=rule.rule_id,
            ),
            "title": rule.title,
            "status": "CONFIRMED",
            "severity": self._severity(score),
            "score": score,
            "confidence": "high",
            "target": target.copy(),
            "evidence": [deepcopy(evidence)],
            "risk_factors": [rule.weight_key],
            "attack_path": None,
            "blast_radius": None,
            "recommendations": [rule.recommendation],
            "limitations": [
                "This finding identifies configuration risk, not exploitation."
            ],
        }

    def _severity(self, score: int) -> str:
        matching = [
            (threshold, severity)
            for severity, threshold in self.severity_thresholds.items()
            if score >= threshold
        ]
        if not matching:
            return "info"
        return max(matching, key=lambda item: item[0])[1]


def analyze_security_context(
    evidence: Iterable[Evidence | Mapping[str, Any]],
    *,
    config_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Convenience wrapper for :class:`SecurityContextRuleEngine`."""

    return SecurityContextRuleEngine(config_path=config_path).analyze(evidence)


# Backwards-friendly descriptive alias for callers that think in rule terms.
evaluate_security_context = analyze_security_context
