"""Tests for the allowlisted, read-only Kubernetes workload collector."""

from datetime import datetime, timezone

import pytest

from src.collectors.kubernetes_workload import KubernetesWorkloadCollector
from src.models import ScanStatus

OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _workload(kind: str, name: str = "payments", namespace: str = "team-a") -> dict:
    pod_spec = {
        "serviceAccountName": "payments",
        "initContainers": [
            {"name": "migrate", "image": "registry.invalid/migrate:1.2.3"}
        ],
        "containers": [
            {"name": "api", "image": "registry.invalid/api@sha256:abc"},
            {"name": "metrics", "image": "registry.invalid/metrics:2.0"},
        ],
    }
    spec = pod_spec if kind == "Pod" else {"template": {"spec": pod_spec}}
    return {
        "apiVersion": "v1" if kind == "Pod" else "apps/v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


class FakeKubernetesClient:
    """Expose approved reads and make every prohibited operation fail loudly."""

    def __init__(self, responses: dict[str, dict] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, str, str]] = []

    def _read(self, method: str, *, name: str, namespace: str) -> dict:
        self.calls.append((method, name, namespace))
        try:
            return self.responses[method]
        except KeyError as exc:
            raise LookupError(f"{namespace}/{name} was not found") from exc

    def read_namespaced_pod(self, *, name: str, namespace: str) -> dict:
        return self._read("read_namespaced_pod", name=name, namespace=namespace)

    def read_namespaced_deployment(self, *, name: str, namespace: str) -> dict:
        return self._read(
            "read_namespaced_deployment", name=name, namespace=namespace
        )

    def read_namespaced_stateful_set(self, *, name: str, namespace: str) -> dict:
        return self._read(
            "read_namespaced_stateful_set", name=name, namespace=namespace
        )

    def read_namespaced_daemon_set(self, *, name: str, namespace: str) -> dict:
        return self._read(
            "read_namespaced_daemon_set", name=name, namespace=namespace
        )

    def __getattr__(self, method: str):
        if any(
            operation in method
            for operation in ("secret", "create", "patch", "update", "delete")
        ):
            raise AssertionError(f"prohibited client method accessed: {method}")
        raise AttributeError(method)


@pytest.mark.parametrize(
    ("kind", "read_method"),
    [
        ("Pod", "read_namespaced_pod"),
        ("Deployment", "read_namespaced_deployment"),
        ("StatefulSet", "read_namespaced_stateful_set"),
        ("DaemonSet", "read_namespaced_daemon_set"),
    ],
)
def test_approved_target_returns_normalized_evidence_and_one_exact_read(
    kind: str, read_method: str
) -> None:
    client = FakeKubernetesClient({read_method: _workload(kind)})
    collector = KubernetesWorkloadCollector(
        client, approved_namespace="team-a", collector_version="test-version"
    )

    result = collector.collect(
        namespace="team-a",
        kind=kind,
        name="payments",
        cluster="test-cluster",
        observed_at=OBSERVED_AT,
    )

    assert result.status is ScanStatus.COMPLETE
    assert result.errors == []
    assert result.target.to_dict() == {
        "cluster": "test-cluster",
        "namespace": "team-a",
        "kind": kind,
        "name": "payments",
        "container": None,
    }
    assert client.calls == [(read_method, "payments", "team-a")]

    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.source == "kubernetes.workload"
    assert evidence.observed_at == OBSERVED_AT
    assert evidence.collector_version == "test-version"
    assert evidence.details["workload"] == {
        "cluster": "test-cluster",
        "namespace": "team-a",
        "kind": kind,
        "name": "payments",
    }
    assert evidence.details["pod_spec"]["serviceAccountName"] == "payments"
    assert evidence.details["container_images"] == [
        {
            "name": "api",
            "type": "container",
            "image": "registry.invalid/api@sha256:abc",
        },
        {
            "name": "metrics",
            "type": "container",
            "image": "registry.invalid/metrics:2.0",
        },
        {
            "name": "migrate",
            "type": "initContainer",
            "image": "registry.invalid/migrate:1.2.3",
        },
    ]


def test_unreadable_workload_returns_collection_failed() -> None:
    client = FakeKubernetesClient()
    collector = KubernetesWorkloadCollector(client, approved_namespace="team-a")

    result = collector.collect(
        namespace="team-a", kind="Deployment", name="missing"
    )

    assert result.status is ScanStatus.COLLECTION_FAILED
    assert result.evidence == []
    assert "failed to read Deployment team-a/missing" in result.errors[0]
    assert "not found" in result.errors[0]
    assert client.calls == [
        ("read_namespaced_deployment", "missing", "team-a")
    ]


@pytest.mark.parametrize("field", ["namespace", "kind", "name"])
def test_explicit_target_fields_are_required_before_any_client_call(
    field: str,
) -> None:
    client = FakeKubernetesClient()
    collector = KubernetesWorkloadCollector(client, approved_namespace="team-a")
    request = {"namespace": "team-a", "kind": "Pod", "name": "payments"}
    request[field] = ""

    with pytest.raises(ValueError, match=field):
        collector.collect(**request)

    assert client.calls == []


def test_unsupported_kind_is_rejected_before_any_client_call() -> None:
    client = FakeKubernetesClient()
    collector = KubernetesWorkloadCollector(client, approved_namespace="team-a")

    with pytest.raises(ValueError, match="unsupported workload kind 'Secret'"):
        collector.collect(namespace="team-a", kind="Secret", name="credentials")

    assert client.calls == []


def test_cross_namespace_request_is_rejected_before_any_client_call() -> None:
    client = FakeKubernetesClient()
    collector = KubernetesWorkloadCollector(client, approved_namespace="team-a")

    with pytest.raises(PermissionError, match="not the approved namespace"):
        collector.collect(namespace="team-b", kind="Pod", name="payments")

    assert client.calls == []


def test_mismatched_response_identity_fails_closed() -> None:
    client = FakeKubernetesClient(
        {"read_namespaced_pod": _workload("Pod", namespace="team-b")}
    )
    collector = KubernetesWorkloadCollector(client, approved_namespace="team-a")

    result = collector.collect(
        namespace="team-a", kind="Pod", name="payments"
    )

    assert result.status is ScanStatus.COLLECTION_FAILED
    assert result.evidence == []
    assert "does not match the requested target" in result.errors[0]
    assert client.calls == [("read_namespaced_pod", "payments", "team-a")]
