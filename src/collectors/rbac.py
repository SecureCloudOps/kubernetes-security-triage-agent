"""Collect declared RBAC permissions for a Kubernetes workload.

The collector consumes an already-read workload and uses only the four RBAC
read operations needed to resolve bindings and roles.  It does not read Secret
objects, impersonate the ServiceAccount, create access-review objects, perform
API discovery, or mutate the cluster.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Mapping

from src.models import Evidence, ScanResult, ScanStatus, Target

COLLECTOR_VERSION = "1.0.0"
EVIDENCE_SOURCE = "kubernetes.rbac"


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
    """Read manifest-style camelCase or Kubernetes-client snake_case keys."""

    for name in names:
        if name in value:
            return value[name]
    return default


def _list(value: Any, field_name: str) -> list[Any]:
    if value is None:
        return []
    value = _plain(value)
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    return value


def _string_list(value: Any, field_name: str, *, required: bool = False) -> list[str]:
    items = _list(value, field_name)
    if not all(isinstance(item, str) for item in items):
        raise ValueError(f"{field_name} must be a list of strings")
    if required and not items:
        raise ValueError(f"{field_name} must not be empty")
    return sorted(set(items))


def _items(response: Any, field_name: str) -> list[Mapping[str, Any]]:
    response = _mapping(response, field_name)
    raw_items = response.get("items")
    if not isinstance(raw_items, list):
        raise ValueError(f"{field_name}.items must be a list")
    return [
        _mapping(item, f"{field_name}.items[{index}]")
        for index, item in enumerate(raw_items)
    ]


def _pod_spec(workload: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    spec = _mapping(workload.get("spec"), "workload.spec")
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job_template = _mapping(
            _field(spec, "jobTemplate", "job_template"),
            "workload.spec.jobTemplate",
        )
        job_spec = _mapping(job_template.get("spec"), "jobTemplate.spec")
        template = _mapping(job_spec.get("template"), "jobTemplate.spec.template")
        return _mapping(template.get("spec"), "jobTemplate.spec.template.spec")
    template = _mapping(spec.get("template"), "workload.spec.template")
    return _mapping(template.get("spec"), "workload.spec.template.spec")


def _workload_identity(
    workload: Mapping[str, Any],
) -> tuple[str, str, str, str]:
    metadata = _mapping(workload.get("metadata"), "workload.metadata")
    namespace = _required_text(
        metadata.get("namespace"), "workload.metadata.namespace"
    )
    kind = _required_text(workload.get("kind"), "workload.kind")
    name = _required_text(metadata.get("name"), "workload.metadata.name")
    raw_service_account = _field(
        _pod_spec(workload, kind),
        "serviceAccountName",
        "service_account_name",
        default="default",
    )
    if raw_service_account is None or raw_service_account == "":
        service_account = "default"
    else:
        service_account = _required_text(
            raw_service_account, "workload pod spec.serviceAccountName"
        )
    return namespace, kind, name, service_account


def _subject_matches(
    subject: Mapping[str, Any], *, namespace: str, service_account: str
) -> bool:
    kind = _required_text(subject.get("kind"), "binding subject.kind")
    name = _required_text(subject.get("name"), "binding subject.name")

    if kind == "ServiceAccount":
        subject_namespace = _required_text(
            subject.get("namespace"), "ServiceAccount subject.namespace"
        )
        return name == service_account and subject_namespace == namespace

    service_account_user = (
        f"system:serviceaccount:{namespace}:{service_account}"
    )
    if kind == "User":
        return name == service_account_user
    if kind == "Group":
        return name in {
            "system:serviceaccounts",
            f"system:serviceaccounts:{namespace}",
            "system:authenticated",
        }
    return False


def _binding_applies(
    binding: Mapping[str, Any], *, namespace: str, service_account: str
) -> bool:
    subjects = _list(binding.get("subjects"), "binding.subjects")
    return any(
        _subject_matches(
            _mapping(subject, f"binding.subjects[{index}]"),
            namespace=namespace,
            service_account=service_account,
        )
        for index, subject in enumerate(subjects)
    )


def _binding_identity(
    binding: Mapping[str, Any], *, kind: str, namespace: str | None
) -> str:
    metadata = _mapping(binding.get("metadata"), f"{kind}.metadata")
    name = _required_text(metadata.get("name"), f"{kind}.metadata.name")
    actual_namespace = metadata.get("namespace")
    if namespace is not None and actual_namespace not in (None, namespace):
        raise ValueError(
            f"{kind} {name!r} belongs to namespace {actual_namespace!r}, "
            f"not requested namespace {namespace!r}"
        )
    return name


def _role_reference(binding: Mapping[str, Any], binding_name: str) -> tuple[str, str]:
    role_ref = _mapping(
        _field(binding, "roleRef", "role_ref"),
        f"binding {binding_name}.roleRef",
    )
    role_kind = _required_text(
        role_ref.get("kind"), f"binding {binding_name}.roleRef.kind"
    )
    if role_kind not in {"Role", "ClusterRole"}:
        raise ValueError(
            f"binding {binding_name}.roleRef.kind must be Role or ClusterRole"
        )
    role_name = _required_text(
        role_ref.get("name"), f"binding {binding_name}.roleRef.name"
    )
    return role_kind, role_name


def _role_rules(
    role: Any,
    *,
    role_kind: str,
    role_name: str,
    namespace: str | None,
) -> list[Mapping[str, Any]]:
    role = _mapping(role, role_kind)
    metadata = _mapping(role.get("metadata"), f"{role_kind}.metadata")
    actual_name = _required_text(
        metadata.get("name"), f"{role_kind}.metadata.name"
    )
    if actual_name != role_name:
        raise ValueError(
            f"{role_kind} response name {actual_name!r} does not match "
            f"requested role {role_name!r}"
        )
    if role_kind == "Role":
        actual_namespace = metadata.get("namespace")
        if actual_namespace not in (None, namespace):
            raise ValueError(
                f"Role {role_name!r} belongs to namespace "
                f"{actual_namespace!r}, not {namespace!r}"
            )

    return [
        _mapping(rule, f"{role_kind} {role_name}.rules[{index}]")
        for index, rule in enumerate(_list(role.get("rules"), f"{role_kind}.rules"))
    ]


def _normalize_rule(
    rule: Mapping[str, Any], *, scope: str, namespace: str | None
) -> dict[str, Any] | None:
    api_groups = _string_list(
        _field(rule, "apiGroups", "api_groups"), "rule.apiGroups"
    )
    resources = _string_list(rule.get("resources"), "rule.resources")
    verbs = _string_list(rule.get("verbs"), "rule.verbs", required=True)
    resource_names = _string_list(
        _field(rule, "resourceNames", "resource_names"), "rule.resourceNames"
    )
    non_resource_urls = _string_list(
        _field(rule, "nonResourceURLs", "non_resource_urls"),
        "rule.nonResourceURLs",
    )

    if not resources and not non_resource_urls:
        raise ValueError("RBAC rule must contain resources or nonResourceURLs")
    if resources and non_resource_urls:
        raise ValueError("RBAC rule cannot mix resources and nonResourceURLs")
    if resource_names and not resources:
        raise ValueError("resourceNames require resource rules")
    if resources and not api_groups:
        raise ValueError("resource rules must include apiGroups")

    # RoleBindings only authorize namespaced requests. Non-resource requests do
    # not have a namespace, so such a ClusterRole rule is not effective through
    # a RoleBinding and must not be reported as an effective permission.
    if non_resource_urls and scope == "namespace":
        return None

    return {
        "api_groups": api_groups,
        "resources": resources,
        "verbs": verbs,
        "resource_names": resource_names,
        "non_resource_urls": non_resource_urls,
        "scope": scope,
        "namespace": namespace,
    }


def _permission_key(permission: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        permission["scope"],
        permission["namespace"] or "",
        tuple(permission["api_groups"]),
        tuple(permission["resources"]),
        tuple(permission["verbs"]),
        tuple(permission["resource_names"]),
        tuple(permission["non_resource_urls"]),
    )


class RBACCollector:
    """Resolve effective declared RBAC rules for a workload ServiceAccount."""

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
        workload: Mapping[str, Any],
        *,
        cluster: str = "unknown",
        observed_at: datetime | str | None = None,
    ) -> ScanResult:
        """Return normalized rules granted to the workload ServiceAccount."""

        workload = _mapping(workload, "workload")
        namespace, kind, name, service_account = _workload_identity(workload)
        cluster = _required_text(cluster, "cluster")

        if namespace != self.approved_namespace:
            raise PermissionError(
                f"namespace {namespace!r} is not the approved namespace "
                f"{self.approved_namespace!r}"
            )

        target = Target(cluster=cluster, namespace=namespace, kind=kind, name=name)
        try:
            role_bindings = _items(
                self._client.list_namespaced_role_binding(namespace=namespace),
                "RoleBinding list",
            )
            cluster_role_bindings = _items(
                self._client.list_cluster_role_binding(),
                "ClusterRoleBinding list",
            )

            resolved_roles: dict[tuple[str, str, str | None], list[Mapping[str, Any]]] = {}
            permissions: dict[tuple[Any, ...], dict[str, Any]] = {}

            binding_sets = (
                ("RoleBinding", role_bindings, "namespace", namespace),
                ("ClusterRoleBinding", cluster_role_bindings, "cluster", None),
            )
            for binding_kind, bindings, scope, permission_namespace in binding_sets:
                for binding in bindings:
                    binding_name = _binding_identity(
                        binding,
                        kind=binding_kind,
                        namespace=namespace if binding_kind == "RoleBinding" else None,
                    )
                    if not _binding_applies(
                        binding,
                        namespace=namespace,
                        service_account=service_account,
                    ):
                        continue

                    role_kind, role_name = _role_reference(binding, binding_name)
                    if binding_kind == "ClusterRoleBinding" and role_kind != "ClusterRole":
                        raise ValueError(
                            f"ClusterRoleBinding {binding_name}.roleRef.kind must be ClusterRole"
                        )

                    role_namespace = namespace if role_kind == "Role" else None
                    role_key = (role_kind, role_name, role_namespace)
                    if role_key not in resolved_roles:
                        if role_kind == "Role":
                            raw_role = self._client.read_namespaced_role(
                                name=role_name, namespace=namespace
                            )
                        else:
                            raw_role = self._client.read_cluster_role(name=role_name)
                        resolved_roles[role_key] = _role_rules(
                            raw_role,
                            role_kind=role_kind,
                            role_name=role_name,
                            namespace=role_namespace,
                        )

                    source = {
                        "binding_kind": binding_kind,
                        "binding_name": binding_name,
                        "binding_namespace": (
                            namespace if binding_kind == "RoleBinding" else None
                        ),
                        "role_kind": role_kind,
                        "role_name": role_name,
                    }
                    for rule in resolved_roles[role_key]:
                        permission = _normalize_rule(
                            rule,
                            scope=scope,
                            namespace=permission_namespace,
                        )
                        if permission is None:
                            continue
                        key = _permission_key(permission)
                        if key not in permissions:
                            permissions[key] = {**permission, "sources": []}
                        if source not in permissions[key]["sources"]:
                            permissions[key]["sources"].append(source)

            normalized_permissions = [permissions[key] for key in sorted(permissions)]
            for permission in normalized_permissions:
                permission["sources"].sort(
                    key=lambda source: (
                        source["binding_kind"],
                        source["binding_namespace"] or "",
                        source["binding_name"],
                        source["role_kind"],
                        source["role_name"],
                    )
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
                    },
                    "service_account": {
                        "name": service_account,
                        "namespace": namespace,
                        "username": (
                            f"system:serviceaccount:{namespace}:{service_account}"
                        ),
                    },
                    "permissions": normalized_permissions,
                    "scope": "declared_rbac_only",
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
                    "failed to collect RBAC permissions for "
                    f"{kind} {namespace}/{name} using ServiceAccount "
                    f"{service_account!r}: {type(exc).__name__}: {exc}"
                ],
            )


def collect_rbac(
    client: Any,
    workload: Mapping[str, Any],
    *,
    approved_namespace: str,
    cluster: str = "unknown",
    observed_at: datetime | str | None = None,
) -> ScanResult:
    """Convenience wrapper for one workload's RBAC collection."""

    return RBACCollector(
        client,
        approved_namespace=approved_namespace,
    ).collect(
        workload,
        cluster=cluster,
        observed_at=observed_at,
    )
