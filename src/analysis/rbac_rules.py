"""Deterministic analysis of normalized Kubernetes RBAC permissions.

The engine consumes only evidence produced by the RBAC collector.  It does not
contact Kubernetes, perform access reviews, expand permissions with discovery,
or use AI.  Results describe declared permissions, not observed use of them.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from src.collectors.rbac import EVIDENCE_SOURCE
from src.models import Evidence, ScanResult, ScanStatus

DEFAULT_RISK_RULES_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "risk-rules.yaml"
)

_REQUIRED_WEIGHTS = {
    "cluster_admin_binding",
    "namespace_admin_permission",
    "secrets_read_permission",
    "rbac_escalation_permission",
    "pod_exec_permission",
}
_READ_VERBS = frozenset({"get", "list", "watch"})
_ESCALATION_VERBS = frozenset({"bind", "escalate", "impersonate"})
_MODIFY_VERBS = frozenset({"create", "update", "patch"})
_DECLARED_PERMISSION_LIMITATION = (
    "This finding describes declared RBAC authorization. It does not prove that "
    "the permission was exercised or that an escalation occurred."
)


def deterministic_rbac_finding_id(
    *, cluster: str, namespace: str, kind: str, workload: str, rule_id: str
) -> str:
    """Return a stable hexadecimal ID for one workload and risk category."""

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


def _evidence_dict(item: Evidence | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(item, Evidence):
        return item.to_dict()
    if isinstance(item, Mapping):
        return deepcopy(dict(item))
    raise TypeError("evidence must contain Evidence objects or mappings")


def _target_from_workload(
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
    """Deduplicate exact observations while retaining complete RBAC provenance."""

    unique = {
        json.dumps(
            item,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ): item
        for item in items
    }
    return [deepcopy(unique[key]) for key in sorted(unique)]


def _string_set(value: Any) -> frozenset[str] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return frozenset(value)


def _permission_fields(
    permission: Any,
) -> tuple[str, frozenset[str], frozenset[str], frozenset[str]] | None:
    if not isinstance(permission, Mapping):
        return None
    scope = permission.get("scope")
    resources = _string_set(permission.get("resources"))
    verbs = _string_set(permission.get("verbs"))
    api_groups = _string_set(permission.get("api_groups"))
    resource_names = _string_set(permission.get("resource_names"))
    sources = permission.get("sources")
    if (
        scope not in {"cluster", "namespace"}
        or resources is None
        or verbs is None
        or api_groups is None
        or resource_names is None
        or not isinstance(sources, list)
    ):
        return None
    return scope, resources, verbs, api_groups


def _allows(values: frozenset[str], requested: str) -> bool:
    return "*" in values or requested in values


def _allows_any(values: frozenset[str], requested: frozenset[str]) -> bool:
    return "*" in values or bool(values.intersection(requested))


def _core_api(api_groups: frozenset[str]) -> bool:
    return "*" in api_groups or "" in api_groups


def _rbac_api(api_groups: frozenset[str]) -> bool:
    return "*" in api_groups or "rbac.authorization.k8s.io" in api_groups


def _categories(permission: Any) -> frozenset[str] | None:
    fields = _permission_fields(permission)
    if fields is None:
        return None
    scope, resources, verbs, api_groups = fields
    categories: set[str] = set()

    if "*" in resources and "*" in verbs:
        categories.add(
            "cluster_admin_binding"
            if scope == "cluster"
            else "namespace_admin_permission"
        )

    if (
        _core_api(api_groups)
        and _allows(resources, "secrets")
        and _allows_any(verbs, _READ_VERBS)
    ):
        categories.add("secrets_read_permission")

    if _allows_any(verbs, _ESCALATION_VERBS):
        categories.add("rbac_escalation_permission")

    modifies_role_bindings = (
        _rbac_api(api_groups)
        and _allows_any(verbs, _MODIFY_VERBS)
        and (
            _allows(resources, "rolebindings")
            or (scope == "cluster" and _allows(resources, "clusterrolebindings"))
        )
    )
    if modifies_role_bindings:
        categories.add("rbac_escalation_permission")

    if (
        _core_api(api_groups)
        and _allows(resources, "pods/exec")
        and _allows(verbs, "create")
    ):
        categories.add("pod_exec_permission")

    return frozenset(categories)


def _scan_failure_evidence(scan: ScanResult) -> dict[str, Any]:
    """Represent a collector failure without inventing RBAC observations."""

    return {
        "source": f"{EVIDENCE_SOURCE}.collection_status",
        "observed_at": "1970-01-01T00:00:00Z",
        "collector_version": "unavailable",
        "details": {
            "workload": scan.target.to_dict(),
            "collection_status": scan.status.value,
            "errors": scan.errors.copy(),
            "observation_available": False,
        },
    }


_FINDING_TEXT = {
    "cluster_admin_binding": (
        "ServiceAccount has cluster-wide wildcard RBAC permissions",
        "Replace the ClusterRoleBinding with the narrowest required verbs and "
        "resources, using namespace scope where possible.",
    ),
    "namespace_admin_permission": (
        "ServiceAccount has namespace-wide wildcard RBAC permissions",
        "Replace wildcard namespace permissions with the specific verbs and "
        "resources required by the workload.",
    ),
    "secrets_read_permission": (
        "ServiceAccount can read Kubernetes Secrets",
        "Remove Secret read access or restrict it to required Secret names with "
        "resourceNames.",
    ),
    "rbac_escalation_permission": (
        "ServiceAccount can escalate or delegate RBAC permissions",
        "Remove bind, escalate, impersonate, and binding-modification permissions "
        "unless they are strictly required.",
    ),
    "pod_exec_permission": (
        "ServiceAccount can execute commands in Pods",
        "Remove create access to pods/exec unless interactive container access is "
        "an explicit workload requirement.",
    ),
}


class RBACRuleEngine:
    """Convert effective declared RBAC evidence into category-level findings."""

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
        """Return one deterministic result per workload and RBAC risk category."""

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

        results: list[dict[str, Any]] = []
        for group in groups.values():
            target = deepcopy(group["target"])
            supporting_evidence = _canonical_evidence(group["evidence"])
            if group["unknown"]:
                results.append(
                    self._insufficient_evidence(
                        target=target, evidence=supporting_evidence
                    )
                )
                continue
            for category in sorted(group["categories"]):
                results.append(
                    self._finding(
                        target=target,
                        evidence=supporting_evidence,
                        risk_factor=category,
                    )
                )

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

    @staticmethod
    def _group(
        groups: dict[tuple[str, str, str, str], dict[str, Any]],
        target: dict[str, str | None],
    ) -> dict[str, Any]:
        return groups.setdefault(
            _target_key(target),
            {"target": target, "categories": set(), "unknown": False, "evidence": []},
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
        target = _target_from_workload(workload)
        if target is None:
            return

        group = self._group(groups, target)
        group["evidence"].append(item)
        if details.get("collection_status") in {
            ScanStatus.PARTIAL.value,
            ScanStatus.INSUFFICIENT_EVIDENCE.value,
            ScanStatus.COLLECTION_FAILED.value,
        }:
            group["unknown"] = True
            return

        permissions = details.get("permissions")
        if not isinstance(permissions, list):
            group["unknown"] = True
            return
        for permission in permissions:
            categories = _categories(permission)
            if categories is None:
                group["unknown"] = True
                continue
            group["categories"].update(categories)

    def _finding(
        self,
        *,
        target: dict[str, str | None],
        evidence: list[dict[str, Any]],
        risk_factor: str,
    ) -> dict[str, Any]:
        score = max(
            self.minimum_score,
            min(self.weights[risk_factor], self.maximum_score, 100),
        )
        title, recommendation = _FINDING_TEXT[risk_factor]
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
            "limitations": [_DECLARED_PERMISSION_LIMITATION],
        }

    def _insufficient_evidence(
        self,
        *,
        target: dict[str, str | None],
        evidence: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "finding_id": self._finding_id(target, "insufficient_evidence"),
            "title": "Workload RBAC permissions could not be determined",
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
                "Collect complete Role, ClusterRole, RoleBinding, and "
                "ClusterRoleBinding evidence before assessing RBAC risk."
            ],
            "limitations": [
                _DECLARED_PERMISSION_LIMITATION,
                "RBAC evidence was missing, invalid, partial, or collection failed.",
            ],
        }

    @staticmethod
    def _finding_id(target: Mapping[str, Any], rule_id: str) -> str:
        return deterministic_rbac_finding_id(
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


def analyze_rbac(
    evidence: Iterable[Evidence | Mapping[str, Any] | ScanResult] | ScanResult,
    *,
    config_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Convenience wrapper for :class:`RBACRuleEngine`."""

    return RBACRuleEngine(config_path=config_path).analyze(evidence)


evaluate_rbac = analyze_rbac
