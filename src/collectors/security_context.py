"""Collect normalized security-context evidence from Kubernetes manifests.

The collector operates entirely on an already-loaded manifest.  It does not
create a Kubernetes client or contact a cluster, which keeps fixture-based and
admission-style use deterministic and side-effect free.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from src.models import Evidence, Target

COLLECTOR_VERSION = "1.0.0"
EVIDENCE_SOURCE = "kubernetes.security_context"

_WORKLOAD_POD_SPEC_PATHS: dict[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}

_CONTAINER_GROUPS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("containers",), "container"),
    (("initContainers", "init_containers"), "initContainer"),
    (("ephemeralContainers", "ephemeral_containers"), "ephemeralContainer"),
)

_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "securityContext": ("securityContext", "security_context"),
    "runAsNonRoot": ("runAsNonRoot", "run_as_non_root"),
    "runAsUser": ("runAsUser", "run_as_user"),
    "allowPrivilegeEscalation": (
        "allowPrivilegeEscalation",
        "allow_privilege_escalation",
    ),
    "readOnlyRootFilesystem": (
        "readOnlyRootFilesystem",
        "read_only_root_filesystem",
    ),
    "seccompProfile": ("seccompProfile", "seccomp_profile"),
    "hostNetwork": ("hostNetwork", "host_network"),
    "hostPID": ("hostPID", "host_pid"),
    "hostIPC": ("hostIPC", "host_ipc"),
}

_MISSING = object()


def _mapping(value: Any, field_path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_path} must be an object")
    return value


def _manifest_pod_spec(workload: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    try:
        path = _WORKLOAD_POD_SPEC_PATHS[kind]
    except KeyError as exc:
        supported = ", ".join(sorted(_WORKLOAD_POD_SPEC_PATHS))
        raise ValueError(
            f"unsupported workload kind {kind!r}; expected one of: {supported}"
        ) from exc

    current: Any = workload
    traversed: list[str] = []
    for component in path:
        traversed.append(component)
        current = _mapping(current, ".".join(traversed[:-1]) or "workload")
        if component not in current:
            raise ValueError(f"missing pod spec field: {'.'.join(traversed)}")
        current = current[component]

    return _mapping(current, ".".join(path))


def _optional_context(value: Any, field_path: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    return _mapping(value, field_path)


def _field(
    value: Mapping[str, Any], names: tuple[str, ...], *, default: Any = None
) -> Any:
    for name in names:
        if name in value:
            return value[name]
    return default


def _setting(value: Mapping[str, Any], name: str, *, default: Any = None) -> Any:
    return _field(value, _FIELD_ALIASES.get(name, (name,)), default=default)


def _effective_setting(
    name: str,
    container_context: Mapping[str, Any],
    pod_context: Mapping[str, Any],
) -> Any:
    """Return a container override, a pod default, or ``None`` when absent."""

    container_value = _setting(container_context, name, default=_MISSING)
    if container_value is not _MISSING and container_value is not None:
        return container_value
    return _setting(pod_context, name)


def _capabilities(container_context: Mapping[str, Any]) -> dict[str, Any]:
    raw_capabilities = _setting(container_context, "capabilities")
    if raw_capabilities is None:
        return {"add": None, "drop": None}

    capabilities = _mapping(
        raw_capabilities, "container.securityContext.capabilities"
    )
    return {
        "add": capabilities.get("add"),
        "drop": capabilities.get("drop"),
    }


def _required_text(value: Any, field_path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_path} must be a non-empty string")
    return value


class SecurityContextCollector:
    """Create one :class:`Evidence` observation for every workload container."""

    def __init__(self, *, collector_version: str = COLLECTOR_VERSION) -> None:
        self.collector_version = _required_text(
            collector_version, "collector_version"
        )

    def collect(
        self,
        pod_spec: Mapping[str, Any],
        *,
        target: Target,
        observed_at: datetime | str | None = None,
    ) -> list[Evidence]:
        """Inspect a normalized pod spec without contacting a cluster.

        Container-level values override the pod security context for the three
        settings Kubernetes allows at both levels: ``runAsNonRoot``,
        ``runAsUser``, and ``seccompProfile``.  All absent settings are emitted
        as ``None`` so callers can distinguish unknown configuration from an
        explicit ``false`` value.
        """

        pod_spec = _mapping(pod_spec, "pod_spec")
        if not isinstance(target, Target):
            raise TypeError("target must be a Target")
        pod_context = _optional_context(
            _setting(pod_spec, "securityContext"), "podSpec.securityContext"
        )
        timestamp = observed_at or datetime.now(timezone.utc)

        evidence: list[Evidence] = []
        for group_names, container_type in _CONTAINER_GROUPS:
            group_name = group_names[0]
            raw_containers = _field(pod_spec, group_names, default=[])
            if raw_containers is None:
                raw_containers = []
            if not isinstance(raw_containers, list):
                raise ValueError(f"podSpec.{group_name} must be a list")

            for index, raw_container in enumerate(raw_containers):
                container = _mapping(
                    raw_container, f"podSpec.{group_name}[{index}]"
                )
                container_name = _required_text(
                    container.get("name"), f"podSpec.{group_name}[{index}].name"
                )
                container_context = _optional_context(
                    _setting(container, "securityContext"),
                    f"podSpec.{group_name}[{index}].securityContext",
                )

                details = {
                    "workload": {
                        "cluster": target.cluster,
                        "namespace": target.namespace,
                        "kind": target.kind,
                        "name": target.name,
                    },
                    "container": {
                        "name": container_name,
                        "type": container_type,
                    },
                    "privileged": _setting(container_context, "privileged"),
                    "runAsNonRoot": _effective_setting(
                        "runAsNonRoot", container_context, pod_context
                    ),
                    "runAsUser": _effective_setting(
                        "runAsUser", container_context, pod_context
                    ),
                    "allowPrivilegeEscalation": _setting(
                        container_context, "allowPrivilegeEscalation"
                    ),
                    "readOnlyRootFilesystem": _setting(
                        container_context, "readOnlyRootFilesystem"
                    ),
                    "capabilities": _capabilities(container_context),
                    "seccompProfile": _effective_setting(
                        "seccompProfile", container_context, pod_context
                    ),
                    "hostNetwork": _setting(pod_spec, "hostNetwork"),
                    "hostPID": _setting(pod_spec, "hostPID"),
                    "hostIPC": _setting(pod_spec, "hostIPC"),
                }
                evidence.append(
                    Evidence(
                        source=EVIDENCE_SOURCE,
                        observed_at=timestamp,
                        collector_version=self.collector_version,
                        details=details,
                    )
                )

        return evidence


def collect_security_context(
    workload: Mapping[str, Any],
    *,
    cluster: str = "unknown",
    observed_at: datetime | str | None = None,
) -> list[Evidence]:
    """Collect from a manifest while preserving the normalized collector contract."""

    workload = _mapping(workload, "workload")
    kind = _required_text(workload.get("kind"), "kind")
    metadata = _mapping(workload.get("metadata"), "metadata")
    target = Target(
        cluster=_required_text(cluster, "cluster"),
        namespace=_required_text(
            metadata.get("namespace", "unknown"), "metadata.namespace"
        ),
        kind=kind,
        name=_required_text(metadata.get("name"), "metadata.name"),
    )
    pod_spec = _manifest_pod_spec(workload, kind)

    return SecurityContextCollector().collect(
        pod_spec,
        target=target,
        observed_at=observed_at,
    )
