"""Tests for namespace-scoped, declaration-only NetworkPolicy collection."""

from datetime import datetime, timezone

import pytest

from src.collectors.network_policy import NetworkPolicyCollector
from src.models import ScanStatus

OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _workload(namespace: str = "team-a") -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "payments", "namespace": namespace},
        "spec": {
            "template": {
                "metadata": {
                    "labels": {
                        "app": "payments",
                        "tier": "api",
                        "environment": "production",
                    }
                },
                "spec": {"containers": [{"name": "api", "image": "api:1"}]},
            }
        },
    }


def _policy(
    name: str,
    *,
    selector: dict | None = None,
    policy_types: list[str] | None = None,
    ingress: list[dict] | None = None,
    egress: list[dict] | None = None,
    namespace: str = "team-a",
) -> dict:
    spec = {
        "podSelector": (
            selector
            if selector is not None
            else {"matchLabels": {"app": "payments"}}
        ),
    }
    if policy_types is not None:
        spec["policyTypes"] = policy_types
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


class FakeKubernetesClient:
    """Expose only the operation permitted to this collector."""

    def __init__(self, policies: list[dict] | Exception):
        self.policies = policies
        self.calls: list[tuple[str, str]] = []

    def list_namespaced_network_policy(self, *, namespace: str) -> dict:
        self.calls.append(("list_namespaced_network_policy", namespace))
        if isinstance(self.policies, Exception):
            raise self.policies
        return {"items": self.policies}

    def __getattr__(self, method: str):
        raise AssertionError(f"prohibited client method accessed: {method}")


def _collect(client: FakeKubernetesClient, workload: dict | None = None):
    return NetworkPolicyCollector(
        client,
        approved_namespace="team-a",
        collector_version="test-version",
    ).collect(
        workload or _workload(),
        cluster="test-cluster",
        observed_at=OBSERVED_AT,
    )


def _details(result):
    assert result.status is ScanStatus.COMPLETE
    return result.evidence[0].details


def test_no_network_policy_leaves_both_directions_non_isolated() -> None:
    client = FakeKubernetesClient([])

    details = _details(_collect(client))

    assert details["ingress_isolated"] is False
    assert details["egress_isolated"] is False
    assert details["matching_policies"] == []
    assert details["policies"] == []
    assert details["enforcement"] == "not_assessed"
    assert client.calls == [("list_namespaced_network_policy", "team-a")]


def test_default_deny_ingress_is_declared_as_ingress_isolation() -> None:
    client = FakeKubernetesClient(
        [_policy("default-deny-ingress", policy_types=["Ingress"], ingress=[])]
    )

    details = _details(_collect(client))

    assert details["ingress_isolated"] is True
    assert details["egress_isolated"] is False
    assert details["matching_policies"] == ["default-deny-ingress"]
    assert details["policies"] == [
        {
            "name": "default-deny-ingress",
            "policy_types": ["Ingress"],
            "pod_selector": {"matchLabels": {"app": "payments"}},
            "ingress": [],
            "egress": [],
        }
    ]


def test_default_deny_ingress_and_egress_isolates_separately() -> None:
    client = FakeKubernetesClient(
        [
            _policy(
                "default-deny-all",
                policy_types=["Ingress", "Egress"],
                ingress=[],
                egress=[],
            )
        ]
    )

    details = _details(_collect(client))

    assert details["ingress_isolated"] is True
    assert details["egress_isolated"] is True
    assert details["matching_policies"] == ["default-deny-all"]


def test_policy_selecting_a_different_workload_does_not_isolate() -> None:
    client = FakeKubernetesClient(
        [
            _policy(
                "other-app",
                selector={"matchLabels": {"app": "orders"}},
                policy_types=["Ingress", "Egress"],
            )
        ]
    )

    details = _details(_collect(client))

    assert details["ingress_isolated"] is False
    assert details["egress_isolated"] is False
    assert details["matching_policies"] == []


def test_empty_pod_selector_selects_all_pods() -> None:
    client = FakeKubernetesClient(
        [_policy("all-pods", selector={}, policy_types=["Ingress"])]
    )

    details = _details(_collect(client))

    assert details["matching_policies"] == ["all-pods"]
    assert details["policies"][0]["pod_selector"] == {}
    assert details["ingress_isolated"] is True


@pytest.mark.parametrize(
    ("expressions", "matches"),
    [
        ([{"key": "tier", "operator": "In", "values": ["api", "worker"]}], True),
        ([{"key": "tier", "operator": "NotIn", "values": ["web"]}], True),
        ([{"key": "environment", "operator": "Exists"}], True),
        ([{"key": "debug", "operator": "DoesNotExist"}], True),
        ([{"key": "tier", "operator": "In", "values": ["web"]}], False),
        ([{"key": "environment", "operator": "DoesNotExist"}], False),
    ],
)
def test_match_expressions(expressions: list[dict], matches: bool) -> None:
    selector = {
        "matchLabels": {"app": "payments"},
        "matchExpressions": expressions,
    }
    client = FakeKubernetesClient(
        [_policy("expression-policy", selector=selector, policy_types=["Egress"])]
    )

    details = _details(_collect(client))

    assert details["egress_isolated"] is matches
    assert details["matching_policies"] == (
        ["expression-policy"] if matches else []
    )
    if matches:
        assert details["policies"][0]["pod_selector"] == selector


def test_policy_types_are_inferred_when_the_field_is_omitted() -> None:
    egress_rules = [
        {"to": [], "ports": [{"protocol": "UDP", "port": 53}]}
    ]
    client = FakeKubernetesClient(
        [
            _policy(
                "allow-dns",
                egress=egress_rules,
            )
        ]
    )

    details = _details(_collect(client))

    assert details["policies"][0]["policy_types"] == ["Ingress", "Egress"]
    assert details["policies"][0]["egress"] == egress_rules
    assert details["ingress_isolated"] is True
    assert details["egress_isolated"] is True


def test_cross_namespace_request_is_rejected_before_api_call() -> None:
    client = FakeKubernetesClient([])
    collector = NetworkPolicyCollector(client, approved_namespace="team-a")

    with pytest.raises(PermissionError, match="not the approved namespace"):
        collector.collect(_workload(namespace="team-b"))

    assert client.calls == []


def test_cross_namespace_policy_in_response_fails_closed() -> None:
    client = FakeKubernetesClient(
        [_policy("foreign", namespace="team-b", policy_types=["Ingress"])]
    )

    result = _collect(client)

    assert result.status is ScanStatus.COLLECTION_FAILED
    assert result.evidence == []
    assert "belongs to namespace 'team-b'" in result.errors[0]


def test_api_failure_fails_closed() -> None:
    client = FakeKubernetesClient(RuntimeError("networking API unavailable"))

    result = _collect(client)

    assert result.status is ScanStatus.COLLECTION_FAILED
    assert result.evidence == []
    assert "failed to collect NetworkPolicies" in result.errors[0]
    assert "networking API unavailable" in result.errors[0]
    assert client.calls == [("list_namespaced_network_policy", "team-a")]
