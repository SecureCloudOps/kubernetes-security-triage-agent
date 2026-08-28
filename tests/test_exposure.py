"""Tests for namespace-scoped Kubernetes exposure collection."""

from datetime import datetime, timezone

import pytest

from src.collectors.exposure import ExposureCollector
from src.models import ScanStatus

OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _workload(namespace: str = "team-a") -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "payments", "namespace": namespace},
        "spec": {
            "template": {
                "metadata": {"labels": {"app": "payments", "tier": "api"}},
                "spec": {"containers": [{"name": "api", "image": "api:1"}]},
            }
        },
    }


def _service(
    name: str = "payments",
    *,
    service_type: str = "ClusterIP",
    selector: dict | None = None,
    external_ips: list[str] | None = None,
    annotations: dict | None = None,
    status_ingress: list[dict] | None = None,
) -> dict:
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": name,
            "namespace": "team-a",
            "annotations": annotations or {},
        },
        "spec": {
            "type": service_type,
            "selector": selector if selector is not None else {"app": "payments"},
            "clusterIP": "10.96.0.20",
            "externalIPs": external_ips or [],
        },
    }
    if status_ingress is not None:
        service["status"] = {"loadBalancer": {"ingress": status_ingress}}
    return service


def _ingress(
    service_name: str = "payments",
    *,
    namespace: str = "team-a",
    status_ingress: list[dict] | None = None,
) -> dict:
    ingress = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": "payments",
            "namespace": namespace,
            "annotations": {"nginx.ingress.kubernetes.io/proxy-body-size": "1m"},
        },
        "spec": {
            "ingressClassName": "nginx",
            "tls": [{"hosts": ["pay.example.com"], "secretName": "payments-tls"}],
            "rules": [
                {
                    "host": "pay.example.com",
                    "http": {
                        "paths": [
                            {
                                "path": "/",
                                "backend": {
                                    "service": {"name": service_name, "port": {"number": 80}}
                                },
                            }
                        ]
                    },
                }
            ],
        },
    }
    if status_ingress is not None:
        ingress["status"] = {"loadBalancer": {"ingress": status_ingress}}
    return ingress


class FakeKubernetesClient:
    """Expose only the two operations permitted to this collector."""

    def __init__(
        self, *, services: list[dict] | Exception, ingresses: list[dict] | Exception
    ):
        self.services = services
        self.ingresses = ingresses
        self.calls: list[tuple[str, str]] = []

    def list_namespaced_service(self, *, namespace: str) -> dict:
        self.calls.append(("list_namespaced_service", namespace))
        if isinstance(self.services, Exception):
            raise self.services
        return {"items": self.services}

    def list_namespaced_ingress(self, *, namespace: str) -> dict:
        self.calls.append(("list_namespaced_ingress", namespace))
        if isinstance(self.ingresses, Exception):
            raise self.ingresses
        return {"items": self.ingresses}

    def __getattr__(self, method: str):
        raise AssertionError(f"prohibited client method accessed: {method}")


def _collect(client: FakeKubernetesClient, workload: dict | None = None):
    return ExposureCollector(
        client,
        approved_namespace="team-a",
        collector_version="test-version",
    ).collect(
        workload or _workload(),
        cluster="test-cluster",
        observed_at=OBSERVED_AT,
    )


def test_internal_cluster_ip() -> None:
    client = FakeKubernetesClient(services=[_service()], ingresses=[])

    result = _collect(client)

    assert result.status is ScanStatus.COMPLETE
    assert result.errors == []
    assert result.evidence[0].details["classification"] == "internal"
    assert result.evidence[0].details["services"][0]["type"] == "ClusterIP"
    assert result.evidence[0].details["services"][0]["classification"] == "internal"
    assert client.calls == [
        ("list_namespaced_service", "team-a"),
        ("list_namespaced_ingress", "team-a"),
    ]


def test_public_load_balancer_requires_assigned_public_endpoint() -> None:
    client = FakeKubernetesClient(
        services=[
            _service(
                service_type="LoadBalancer",
                status_ingress=[{"ip": "34.120.10.20"}],
            )
        ],
        ingresses=[],
    )

    result = _collect(client)

    details = result.evidence[0].details
    assert details["classification"] == "confirmed_external"
    assert details["services"][0]["loadBalancerIngress"] == [
        {"ip": "34.120.10.20"}
    ]


def test_unassigned_load_balancer_is_not_automatically_confirmed_external() -> None:
    client = FakeKubernetesClient(
        services=[_service(service_type="LoadBalancer")], ingresses=[]
    )

    result = _collect(client)

    assert result.evidence[0].details["classification"] == "potentially_external"


def test_internal_load_balancer_annotation_prevents_public_classification() -> None:
    client = FakeKubernetesClient(
        services=[
            _service(
                service_type="LoadBalancer",
                annotations={
                    "service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"
                },
                status_ingress=[
                    {"hostname": "internal-payments.elb.amazonaws.com"}
                ],
            )
        ],
        ingresses=[],
    )

    result = _collect(client)

    assert result.evidence[0].details["classification"] == "internal"


def test_external_ip_is_recorded_and_classified_from_address_scope() -> None:
    client = FakeKubernetesClient(
        services=[_service(external_ips=["8.8.8.8"])], ingresses=[]
    )

    result = _collect(client)

    service = result.evidence[0].details["services"][0]
    assert service["externalIPs"] == ["8.8.8.8"]
    assert service["classification"] == "confirmed_external"


def test_node_port_is_potentially_external() -> None:
    client = FakeKubernetesClient(
        services=[_service(service_type="NodePort")], ingresses=[]
    )

    result = _collect(client)

    assert result.evidence[0].details["classification"] == "potentially_external"


def test_ingress_backed_service_records_hosts_tls_class_and_annotations() -> None:
    client = FakeKubernetesClient(
        services=[_service()],
        ingresses=[_ingress(status_ingress=[{"hostname": "public.example.net"}])],
    )

    result = _collect(client)

    details = result.evidence[0].details
    assert details["classification"] == "confirmed_external"
    assert details["ingresses"] == [
        {
            "name": "payments",
            "services": ["payments"],
            "hosts": ["pay.example.com"],
            "tls": [{"hosts": ["pay.example.com"], "secretName": "payments-tls"}],
            "class": "nginx",
            "annotations": {"nginx.ingress.kubernetes.io/proxy-body-size": "1m"},
            "loadBalancerIngress": [{"hostname": "public.example.net"}],
            "classification": "confirmed_external",
            "reasons": ["Ingress has an assigned public-facing endpoint"],
        }
    ]


def test_unassigned_ingress_is_only_potentially_external() -> None:
    client = FakeKubernetesClient(services=[_service()], ingresses=[_ingress()])

    result = _collect(client)

    assert result.evidence[0].details["classification"] == "potentially_external"


def test_no_matching_service_is_unknown() -> None:
    client = FakeKubernetesClient(
        services=[_service(selector={"app": "other"})],
        ingresses=[_ingress()],
    )

    result = _collect(client)

    details = result.evidence[0].details
    assert details["classification"] == "unknown"
    assert details["services"] == []
    assert details["ingresses"] == []


def test_cross_namespace_request_is_rejected_before_api_calls() -> None:
    client = FakeKubernetesClient(services=[], ingresses=[])
    collector = ExposureCollector(client, approved_namespace="team-a")

    with pytest.raises(PermissionError, match="not the approved namespace"):
        collector.collect(_workload(namespace="team-b"))

    assert client.calls == []


@pytest.mark.parametrize(
    ("services", "ingresses", "expected_calls"),
    [
        (
            RuntimeError("service API unavailable"),
            [],
            [("list_namespaced_service", "team-a")],
        ),
        (
            [_service()],
            RuntimeError("ingress API unavailable"),
            [
                ("list_namespaced_service", "team-a"),
                ("list_namespaced_ingress", "team-a"),
            ],
        ),
    ],
)
def test_failed_api_calls_fail_closed(services, ingresses, expected_calls) -> None:
    client = FakeKubernetesClient(services=services, ingresses=ingresses)

    result = _collect(client)

    assert result.status is ScanStatus.COLLECTION_FAILED
    assert result.evidence == []
    assert "failed to collect exposure" in result.errors[0]
    assert "API unavailable" in result.errors[0]
    assert client.calls == expected_calls
