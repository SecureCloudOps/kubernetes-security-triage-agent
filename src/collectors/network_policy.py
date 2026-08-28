"""Collect declared NetworkPolicy isolation for one Kubernetes workload.

Only NetworkPolicies in the explicitly approved namespace are listed.  The
collector evaluates their pod selectors against already-known workload pod
labels; it does not read pods, inspect a CNI, test connectivity, or mutate the
cluster.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Mapping

from src.models import Evidence, ScanResult, ScanStatus, Target

COLLECTOR_VERSION = "1.0.0"
EVIDENCE_SOURCE = "kubernetes.network_policy"

_MISSING = object()
_POLICY_TYPES = {"Ingress", "Egress"}
_EXPRESSION_OPERATORS = {"In", "NotIn", "Exists", "DoesNotExist"}


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _plain(value: Any) -> Any:
    """Convert Kubernetes client models into JSON-compatible values."""

    if hasattr(value, "to_dict") and callable(value.to_dict):
        value = value.to_dict()
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, Enum):
        return _plain(value.value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError(f"unsupported Kubernetes response value: {type(value).__name__}")


def _mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    value = _plain(value)
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be an object")
    return value


def _field(value: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    """Read manifest-style camelCase or Kubernetes client snake_case keys."""

    for name in names:
        if name in value:
            return value[name]
    return default


def _string_mapping(value: Any, field_name: str) -> dict[str, str]:
    if value is None:
        return {}
    value = _mapping(value, field_name)
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(item, str):
            raise ValueError(f"{field_name}.{key} must be a string")
        result[str(key)] = item
    return result


def _items(response: Any) -> list[Mapping[str, Any]]:
    response = _mapping(response, "network policy list")
    raw_items = response.get("items")
    if not isinstance(raw_items, list):
        raise ValueError("network policy list.items must be a list")
    return [
        _mapping(item, f"network policy list.items[{index}]")
        for index, item in enumerate(raw_items)
    ]


def _pod_labels(workload: Mapping[str, Any]) -> dict[str, str]:
    kind = _required_text(workload.get("kind"), "workload.kind")
    metadata = _mapping(workload.get("metadata"), "workload.metadata")
    if kind == "Pod":
        pod_metadata = metadata
    elif kind == "CronJob":
        spec = _mapping(workload.get("spec"), "workload.spec")
        job_template = _mapping(
            _field(spec, "jobTemplate", "job_template"),
            "workload.spec.jobTemplate",
        )
        job_spec = _mapping(job_template.get("spec"), "jobTemplate.spec")
        template = _mapping(job_spec.get("template"), "jobTemplate.spec.template")
        pod_metadata = _mapping(template.get("metadata"), "podTemplate.metadata")
    else:
        spec = _mapping(workload.get("spec"), "workload.spec")
        template = _mapping(spec.get("template"), "workload.spec.template")
        pod_metadata = _mapping(template.get("metadata"), "podTemplate.metadata")
    return _string_mapping(pod_metadata.get("labels"), "pod labels")


def _selector_parts(
    raw_selector: Any, field_name: str
) -> tuple[dict[str, Any], dict[str, str], list[Mapping[str, Any]]]:
    selector = _mapping(raw_selector, field_name)
    match_labels = _string_mapping(
        _field(selector, "matchLabels", "match_labels"),
        f"{field_name}.matchLabels",
    )
    raw_expressions = _field(
        selector, "matchExpressions", "match_expressions", default=[]
    )
    if raw_expressions is None:
        raw_expressions = []
    if not isinstance(raw_expressions, list):
        raise ValueError(f"{field_name}.matchExpressions must be a list")
    expressions = [
        _mapping(item, f"{field_name}.matchExpressions[{index}]")
        for index, item in enumerate(raw_expressions)
    ]

    # Emit a stable manifest-style selector while retaining every selector
    # requirement relevant to Kubernetes matching semantics.
    normalized: dict[str, Any] = {}
    if match_labels:
        normalized["matchLabels"] = match_labels
    if expressions:
        normalized["matchExpressions"] = [_plain(item) for item in expressions]
    return normalized, match_labels, expressions


def _expression_matches(
    expression: Mapping[str, Any], labels: Mapping[str, str], field_name: str
) -> bool:
    key = _required_text(expression.get("key"), f"{field_name}.key")
    operator = _required_text(expression.get("operator"), f"{field_name}.operator")
    if operator not in _EXPRESSION_OPERATORS:
        supported = ", ".join(sorted(_EXPRESSION_OPERATORS))
        raise ValueError(
            f"{field_name}.operator must be one of: {supported}"
        )

    values = expression.get("values", [])
    if values is None:
        values = []
    if not isinstance(values, list) or not all(
        isinstance(value, str) for value in values
    ):
        raise ValueError(f"{field_name}.values must be a list of strings")

    if operator in {"In", "NotIn"} and not values:
        raise ValueError(f"{field_name}.values must not be empty for {operator}")
    if operator in {"Exists", "DoesNotExist"} and values:
        raise ValueError(f"{field_name}.values must be empty for {operator}")

    if operator == "In":
        return key in labels and labels[key] in values
    if operator == "NotIn":
        return key not in labels or labels[key] not in values
    if operator == "Exists":
        return key in labels
    return key not in labels


def _selector_matches(
    match_labels: Mapping[str, str],
    expressions: list[Mapping[str, Any]],
    labels: Mapping[str, str],
    field_name: str,
) -> bool:
    if not all(labels.get(key) == value for key, value in match_labels.items()):
        return False
    return all(
        _expression_matches(
            expression,
            labels,
            f"{field_name}.matchExpressions[{index}]",
        )
        for index, expression in enumerate(expressions)
    )


def _rules(value: Any, field_name: str) -> list[Any]:
    if value is None:
        return []
    value = _plain(value)
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    return value


def _effective_policy_types(
    raw_types: Any, *, egress_rules: list[Any], field_name: str
) -> list[str]:
    if raw_types is None or raw_types == []:
        inferred = ["Ingress"]
        if egress_rules:
            inferred.append("Egress")
        return inferred
    if not isinstance(raw_types, list) or not all(
        isinstance(item, str) for item in raw_types
    ):
        raise ValueError(f"{field_name} must be a list of strings")
    invalid = [item for item in raw_types if item not in _POLICY_TYPES]
    if invalid:
        raise ValueError(f"{field_name} contains unsupported policy types: {invalid}")
    return list(raw_types)


def _matching_policy(
    policy: Mapping[str, Any], *, namespace: str, pod_labels: Mapping[str, str]
) -> dict[str, Any] | None:
    metadata = _mapping(policy.get("metadata"), "NetworkPolicy.metadata")
    name = _required_text(metadata.get("name"), "NetworkPolicy.metadata.name")
    actual_namespace = metadata.get("namespace")
    if actual_namespace is not None and actual_namespace != namespace:
        raise ValueError(
            f"NetworkPolicy {name!r} belongs to namespace "
            f"{actual_namespace!r}, not requested namespace {namespace!r}"
        )

    spec = _mapping(policy.get("spec"), f"NetworkPolicy {name}.spec")
    raw_selector = _field(spec, "podSelector", "pod_selector", default=_MISSING)
    if raw_selector is _MISSING or raw_selector is None:
        raise ValueError(f"NetworkPolicy {name}.spec.podSelector is required")
    selector, match_labels, expressions = _selector_parts(
        raw_selector, f"NetworkPolicy {name}.spec.podSelector"
    )
    if not _selector_matches(
        match_labels,
        expressions,
        pod_labels,
        f"NetworkPolicy {name}.spec.podSelector",
    ):
        return None

    ingress = _rules(spec.get("ingress"), f"NetworkPolicy {name}.spec.ingress")
    egress = _rules(spec.get("egress"), f"NetworkPolicy {name}.spec.egress")
    policy_types = _effective_policy_types(
        _field(spec, "policyTypes", "policy_types"),
        egress_rules=egress,
        field_name=f"NetworkPolicy {name}.spec.policyTypes",
    )
    return {
        "name": name,
        "policy_types": policy_types,
        "pod_selector": selector,
        "ingress": ingress,
        "egress": egress,
    }


class NetworkPolicyCollector:
    """Evaluate declared NetworkPolicy isolation in one approved namespace."""

    def __init__(
        self,
        client: Any,
        *,
        approved_namespace: str,
        collector_version: str = COLLECTOR_VERSION,
    ) -> None:
        if client is None:
            raise ValueError("client is required")
        self._client = client
        self.approved_namespace = _required_text(
            approved_namespace, "approved_namespace"
        )
        self.collector_version = _required_text(
            collector_version, "collector_version"
        )

    def collect(
        self,
        workload: Mapping[str, Any] | None = None,
        *,
        namespace: str | None = None,
        kind: str | None = None,
        name: str | None = None,
        pod_labels: Mapping[str, str] | None = None,
        cluster: str = "unknown",
        observed_at: datetime | str | None = None,
    ) -> ScanResult:
        """Return isolation declared by policies selecting this workload's pods."""

        if workload is not None:
            workload = _mapping(workload, "workload")
            metadata = _mapping(workload.get("metadata"), "workload.metadata")
            derived_namespace = _required_text(
                metadata.get("namespace"), "workload.metadata.namespace"
            )
            derived_kind = _required_text(workload.get("kind"), "workload.kind")
            derived_name = _required_text(
                metadata.get("name"), "workload.metadata.name"
            )
            derived_labels = _pod_labels(workload)
            for supplied, derived, field_name in (
                (namespace, derived_namespace, "namespace"),
                (kind, derived_kind, "kind"),
                (name, derived_name, "name"),
            ):
                if supplied is not None and supplied != derived:
                    raise ValueError(f"{field_name} does not match workload identity")
            if pod_labels is not None and dict(pod_labels) != derived_labels:
                raise ValueError("pod_labels do not match workload pod labels")
            namespace, kind, name, pod_labels = (
                derived_namespace,
                derived_kind,
                derived_name,
                derived_labels,
            )

        namespace = _required_text(namespace, "namespace")
        kind = _required_text(kind, "kind")
        name = _required_text(name, "name")
        cluster = _required_text(cluster, "cluster")
        pod_labels = _string_mapping(pod_labels, "pod_labels")

        if namespace != self.approved_namespace:
            raise PermissionError(
                f"namespace {namespace!r} is not the approved namespace "
                f"{self.approved_namespace!r}"
            )

        target = Target(cluster=cluster, namespace=namespace, kind=kind, name=name)
        try:
            response = self._client.list_namespaced_network_policy(
                namespace=namespace
            )
            matching = [
                collected
                for policy in _items(response)
                if (
                    collected := _matching_policy(
                        policy, namespace=namespace, pod_labels=pod_labels
                    )
                )
                is not None
            ]
            ingress_isolated = any(
                "Ingress" in policy["policy_types"] for policy in matching
            )
            egress_isolated = any(
                "Egress" in policy["policy_types"] for policy in matching
            )

            evidence = Evidence(
                source=EVIDENCE_SOURCE,
                observed_at=observed_at or datetime.now(timezone.utc),
                collector_version=self.collector_version,
                details={
                    "workload": {
                        "cluster": cluster,
                        "namespace": namespace,
                        "kind": kind,
                        "name": name,
                        "pod_labels": dict(pod_labels),
                    },
                    "ingress_isolated": ingress_isolated,
                    "egress_isolated": egress_isolated,
                    "matching_policies": [policy["name"] for policy in matching],
                    "policies": matching,
                    "scope": "declared_configuration_only",
                    "enforcement": "not_assessed",
                },
            )
            return ScanResult(
                target=target,
                status=ScanStatus.COMPLETE,
                evidence=[evidence],
            )
        except Exception as exc:
            return ScanResult(
                target=target,
                status=ScanStatus.COLLECTION_FAILED,
                errors=[
                    "failed to collect NetworkPolicies for "
                    f"{kind} {namespace}/{name}: {type(exc).__name__}: {exc}"
                ],
            )


def collect_network_policy(
    client: Any,
    workload: Mapping[str, Any] | None = None,
    *,
    approved_namespace: str,
    namespace: str | None = None,
    kind: str | None = None,
    name: str | None = None,
    pod_labels: Mapping[str, str] | None = None,
    cluster: str = "unknown",
    observed_at: datetime | str | None = None,
) -> ScanResult:
    """Convenience wrapper for one NetworkPolicy collection."""

    return NetworkPolicyCollector(
        client,
        approved_namespace=approved_namespace,
    ).collect(
        workload,
        namespace=namespace,
        kind=kind,
        name=name,
        pod_labels=pod_labels,
        cluster=cluster,
        observed_at=observed_at,
    )
