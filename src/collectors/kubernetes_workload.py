"""Read one explicitly approved Kubernetes workload.

This module deliberately accepts an already-constructed Kubernetes API client.
It has no kubeconfig loading or discovery behavior, and its method allowlist is
kept here so unsupported resources cannot select arbitrary client methods.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Mapping

from src.models import Evidence, ScanResult, ScanStatus, Target

COLLECTOR_VERSION = "1.0.0"
EVIDENCE_SOURCE = "kubernetes.workload"

_READ_METHODS: dict[str, str] = {
    "Pod": "read_namespaced_pod",
    "Deployment": "read_namespaced_deployment",
    "StatefulSet": "read_namespaced_stateful_set",
    "DaemonSet": "read_namespaced_daemon_set",
}

_CONTAINER_GROUPS: tuple[tuple[str, str], ...] = (
    ("containers", "container"),
    ("initContainers", "initContainer"),
    ("ephemeralContainers", "ephemeralContainer"),
)


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _plain(value: Any) -> Any:
    """Convert Kubernetes model values into JSON-compatible evidence."""

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


def _pod_spec(workload: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    spec = _mapping(workload.get("spec"), "workload.spec")
    if kind == "Pod":
        return spec

    template = _mapping(spec.get("template"), "workload.spec.template")
    return _mapping(template.get("spec"), "workload.spec.template.spec")


def _container_images(pod_spec: Mapping[str, Any]) -> list[dict[str, str]]:
    images: list[dict[str, str]] = []
    for group_name, container_type in _CONTAINER_GROUPS:
        containers = pod_spec.get(group_name, [])
        if containers is None:
            containers = []
        if not isinstance(containers, list):
            raise ValueError(f"pod spec {group_name} must be a list")

        for index, raw_container in enumerate(containers):
            container = _mapping(
                raw_container, f"pod spec {group_name}[{index}]"
            )
            images.append(
                {
                    "name": _required_text(
                        container.get("name"),
                        f"pod spec {group_name}[{index}].name",
                    ),
                    "type": container_type,
                    "image": _required_text(
                        container.get("image"),
                        f"pod spec {group_name}[{index}].image",
                    ),
                }
            )
    return images


class KubernetesWorkloadCollector:
    """Collect normalized evidence for one workload in one approved namespace.

    ``client`` may be a small facade exposing all four allowed read methods. For
    the standard Kubernetes Python client, pass ``CoreV1Api`` as ``client`` and
    ``AppsV1Api`` as ``apps_client``.
    """

    def __init__(
        self,
        client: Any,
        *,
        approved_namespace: str,
        apps_client: Any | None = None,
        collector_version: str = COLLECTOR_VERSION,
    ) -> None:
        if client is None:
            raise ValueError("client is required")
        self._core_client = client
        self._apps_client = apps_client if apps_client is not None else client
        self.approved_namespace = _required_text(
            approved_namespace, "approved_namespace"
        )
        self.collector_version = _required_text(
            collector_version, "collector_version"
        )

    def collect(
        self,
        *,
        namespace: str,
        kind: str,
        name: str,
        cluster: str = "unknown",
        observed_at: datetime | str | None = None,
    ) -> ScanResult:
        """Read exactly one named workload and return normalized evidence.

        Request validation happens before client selection or invocation. Client
        read errors and invalid/mismatched responses become ``COLLECTION_FAILED``
        results so a failed collection can never be interpreted as clean.
        """

        namespace = _required_text(namespace, "namespace")
        kind = _required_text(kind, "kind")
        name = _required_text(name, "name")
        cluster = _required_text(cluster, "cluster")

        if namespace != self.approved_namespace:
            raise PermissionError(
                f"namespace {namespace!r} is not the approved namespace "
                f"{self.approved_namespace!r}"
            )
        if kind not in _READ_METHODS:
            supported = ", ".join(_READ_METHODS)
            raise ValueError(
                f"unsupported workload kind {kind!r}; expected one of: {supported}"
            )

        target = Target(
            cluster=cluster,
            namespace=namespace,
            kind=kind,
            name=name,
        )
        client = self._core_client if kind == "Pod" else self._apps_client
        method_name = _READ_METHODS[kind]

        try:
            read = getattr(client, method_name)
            raw_workload = read(name=name, namespace=namespace)
            workload = _mapping(raw_workload, "workload")
            metadata = _mapping(workload.get("metadata"), "workload.metadata")

            actual_namespace = _required_text(
                metadata.get("namespace"), "workload.metadata.namespace"
            )
            actual_name = _required_text(
                metadata.get("name"), "workload.metadata.name"
            )
            actual_kind = _required_text(workload.get("kind"), "workload.kind")
            if (actual_namespace, actual_kind, actual_name) != (
                namespace,
                kind,
                name,
            ):
                raise ValueError(
                    "Kubernetes response identity does not match the requested target"
                )

            pod_spec = _pod_spec(workload, kind)
            images = _container_images(pod_spec)
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
                    "pod_spec": dict(pod_spec),
                    "container_images": images,
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
                    f"failed to read {kind} {namespace}/{name}: "
                    f"{type(exc).__name__}: {exc}"
                ],
            )


def collect_kubernetes_workload(
    client: Any,
    *,
    approved_namespace: str,
    namespace: str,
    kind: str,
    name: str,
    cluster: str = "unknown",
    apps_client: Any | None = None,
    observed_at: datetime | str | None = None,
) -> ScanResult:
    """Convenience wrapper for a single workload collection."""

    return KubernetesWorkloadCollector(
        client,
        approved_namespace=approved_namespace,
        apps_client=apps_client,
    ).collect(
        namespace=namespace,
        kind=kind,
        name=name,
        cluster=cluster,
        observed_at=observed_at,
    )
