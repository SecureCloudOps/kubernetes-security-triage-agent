"""Tests for read-only effective RBAC permission collection."""

from datetime import datetime, timezone

import pytest

from src.collectors.rbac import RBACCollector
from src.models import ScanStatus

OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _workload(
    *,
    namespace: str = "team-a",
    service_account: str | None = "payments",
) -> dict:
    pod_spec: dict = {"containers": [{"name": "api", "image": "api:1"}]}
    if service_account is not None:
        pod_spec["serviceAccountName"] = service_account
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "payments", "namespace": namespace},
        "spec": {"template": {"spec": pod_spec}},
    }


def _subject(
    name: str = "payments",
    *,
    namespace: str = "team-a",
    kind: str = "ServiceAccount",
) -> dict:
    subject = {"kind": kind, "name": name}
    if kind == "ServiceAccount":
        subject["namespace"] = namespace
    return subject


def _role_binding(
    name: str,
    role_name: str,
    *,
    role_kind: str = "Role",
    subjects: list[dict] | None = None,
    namespace: str = "team-a",
) -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "subjects": subjects if subjects is not None else [_subject()],
        "roleRef": {"kind": role_kind, "name": role_name},
    }


def _cluster_role_binding(
    name: str,
    role_name: str,
    *,
    subjects: list[dict] | None = None,
) -> dict:
    return {
        "metadata": {"name": name},
        "subjects": subjects if subjects is not None else [_subject()],
        "roleRef": {"kind": "ClusterRole", "name": role_name},
    }


def _role(name: str, rules: list[dict], *, namespace: str = "team-a") -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "rules": rules,
    }


def _cluster_role(name: str, rules: list[dict]) -> dict:
    return {"metadata": {"name": name}, "rules": rules}


class FakeRBACClient:
    """Expose exactly the four API operations allowed for RBAC collection."""

    def __init__(
        self,
        *,
        role_bindings: list[dict] | Exception | None = None,
        cluster_role_bindings: list[dict] | Exception | None = None,
        roles: dict[str, dict | Exception] | None = None,
        cluster_roles: dict[str, dict | Exception] | None = None,
    ) -> None:
        self.role_bindings = role_bindings if role_bindings is not None else []
        self.cluster_role_bindings = (
            cluster_role_bindings if cluster_role_bindings is not None else []
        )
        self.roles = roles or {}
        self.cluster_roles = cluster_roles or {}
        self.calls: list[tuple] = []

    def list_namespaced_role_binding(self, *, namespace: str) -> dict:
        self.calls.append(("list_namespaced_role_binding", namespace))
        if isinstance(self.role_bindings, Exception):
            raise self.role_bindings
        return {"items": self.role_bindings}

    def read_namespaced_role(self, *, name: str, namespace: str) -> dict:
        self.calls.append(("read_namespaced_role", name, namespace))
        response = self.roles[name]
        if isinstance(response, Exception):
            raise response
        return response

    def list_cluster_role_binding(self) -> dict:
        self.calls.append(("list_cluster_role_binding",))
        if isinstance(self.cluster_role_bindings, Exception):
            raise self.cluster_role_bindings
        return {"items": self.cluster_role_bindings}

    def read_cluster_role(self, *, name: str) -> dict:
        self.calls.append(("read_cluster_role", name))
        response = self.cluster_roles[name]
        if isinstance(response, Exception):
            raise response
        return response

    def __getattr__(self, method: str):
        raise AssertionError(f"prohibited client method accessed: {method}")


def _collect(client: FakeRBACClient, workload: dict | None = None):
    return RBACCollector(
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
    assert result.errors == []
    return result.evidence[0].details


def test_no_bindings_and_omitted_service_account_uses_default() -> None:
    client = FakeRBACClient()

    details = _details(_collect(client, _workload(service_account=None)))

    assert details["service_account"] == {
        "name": "default",
        "namespace": "team-a",
        "username": "system:serviceaccount:team-a:default",
    }
    assert details["permissions"] == []
    assert client.calls == [
        ("list_namespaced_role_binding", "team-a"),
        ("list_cluster_role_binding",),
    ]


def test_namespaced_role_binding_resolves_role() -> None:
    client = FakeRBACClient(
        role_bindings=[_role_binding("read-config", "config-reader")],
        roles={
            "config-reader": _role(
                "config-reader",
                [
                    {
                        "apiGroups": [""],
                        "resources": ["configmaps"],
                        "verbs": ["get", "list"],
                        "resourceNames": ["app-config"],
                    }
                ],
            )
        },
    )

    permissions = _details(_collect(client))["permissions"]

    assert permissions == [
        {
            "api_groups": [""],
            "resources": ["configmaps"],
            "verbs": ["get", "list"],
            "resource_names": ["app-config"],
            "non_resource_urls": [],
            "scope": "namespace",
            "namespace": "team-a",
            "sources": [
                {
                    "binding_kind": "RoleBinding",
                    "binding_name": "read-config",
                    "binding_namespace": "team-a",
                    "role_kind": "Role",
                    "role_name": "config-reader",
                }
            ],
        }
    ]


def test_role_binding_referencing_cluster_role_remains_namespace_scoped() -> None:
    client = FakeRBACClient(
        role_bindings=[
            _role_binding(
                "view-workloads", "workload-viewer", role_kind="ClusterRole"
            )
        ],
        cluster_roles={
            "workload-viewer": _cluster_role(
                "workload-viewer",
                [
                    {
                        "apiGroups": ["apps"],
                        "resources": ["deployments"],
                        "verbs": ["get", "list"],
                    },
                    {"nonResourceURLs": ["/healthz"], "verbs": ["get"]},
                ],
            )
        },
    )

    permissions = _details(_collect(client))["permissions"]

    assert len(permissions) == 1
    assert permissions[0]["scope"] == "namespace"
    assert permissions[0]["namespace"] == "team-a"
    assert permissions[0]["resources"] == ["deployments"]
    assert permissions[0]["sources"][0]["role_kind"] == "ClusterRole"


def test_cluster_role_binding_grants_cluster_and_non_resource_permissions() -> None:
    client = FakeRBACClient(
        cluster_role_bindings=[
            _cluster_role_binding("discovery", "api-discovery")
        ],
        cluster_roles={
            "api-discovery": _cluster_role(
                "api-discovery",
                [{"nonResourceURLs": ["/api", "/apis", "/healthz*"], "verbs": ["get"]}],
            )
        },
    )

    permission = _details(_collect(client))["permissions"][0]

    assert permission["api_groups"] == []
    assert permission["resources"] == []
    assert permission["non_resource_urls"] == ["/api", "/apis", "/healthz*"]
    assert permission["scope"] == "cluster"
    assert permission["namespace"] is None
    assert permission["sources"][0]["binding_name"] == "discovery"


def test_wrong_service_account_or_namespace_does_not_apply() -> None:
    client = FakeRBACClient(
        role_bindings=[
            _role_binding(
                "wrong-name", "reader", subjects=[_subject("orders")]
            ),
            _role_binding(
                "wrong-namespace",
                "reader",
                subjects=[_subject(namespace="team-b")],
            ),
            _role_binding(
                "wrong-group",
                "reader",
                subjects=[
                    _subject(
                        "system:serviceaccounts:team-b",
                        kind="Group",
                    )
                ],
            ),
        ],
        roles={"reader": _role("reader", [])},
    )

    assert _details(_collect(client))["permissions"] == []
    assert all(call[0] != "read_namespaced_role" for call in client.calls)


@pytest.mark.parametrize(
    "subject",
    [
        _subject("system:serviceaccounts", kind="Group"),
        _subject("system:serviceaccounts:team-a", kind="Group"),
        _subject("system:authenticated", kind="Group"),
        _subject("system:serviceaccount:team-a:payments", kind="User"),
    ],
)
def test_service_account_identity_groups_apply(subject: dict) -> None:
    client = FakeRBACClient(
        cluster_role_bindings=[
            _cluster_role_binding("authenticated-read", "pod-reader", subjects=[subject])
        ],
        cluster_roles={
            "pod-reader": _cluster_role(
                "pod-reader",
                [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
            )
        },
    )

    assert len(_details(_collect(client))["permissions"]) == 1


def test_wildcard_permissions_are_preserved() -> None:
    client = FakeRBACClient(
        cluster_role_bindings=[_cluster_role_binding("admin", "admin")],
        cluster_roles={
            "admin": _cluster_role(
                "admin",
                [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
            )
        },
    )

    permission = _details(_collect(client))["permissions"][0]

    assert permission["api_groups"] == ["*"]
    assert permission["resources"] == ["*"]
    assert permission["verbs"] == ["*"]


def test_secret_read_permissions_are_reported_without_reading_secrets() -> None:
    client = FakeRBACClient(
        role_bindings=[_role_binding("secret-access", "secret-reader")],
        roles={
            "secret-reader": _role(
                "secret-reader",
                [
                    {
                        "apiGroups": [""],
                        "resources": ["secrets"],
                        "verbs": ["get", "list", "watch"],
                    }
                ],
            )
        },
    )

    permission = _details(_collect(client))["permissions"][0]

    assert permission["resources"] == ["secrets"]
    assert permission["verbs"] == ["get", "list", "watch"]
    assert {call[0] for call in client.calls} <= {
        "list_namespaced_role_binding",
        "read_namespaced_role",
        "list_cluster_role_binding",
        "read_cluster_role",
    }


def test_api_failure_fails_closed() -> None:
    client = FakeRBACClient(
        role_bindings=RuntimeError("RBAC API unavailable")
    )

    result = _collect(client)

    assert result.status is ScanStatus.COLLECTION_FAILED
    assert result.evidence == []
    assert "failed to collect RBAC permissions" in result.errors[0]
    assert "RBAC API unavailable" in result.errors[0]
    assert client.calls == [("list_namespaced_role_binding", "team-a")]


def test_duplicate_rules_are_removed_and_provenance_is_retained() -> None:
    duplicate_rule = {
        "apiGroups": [""],
        "resources": ["pods", "pods"],
        "verbs": ["list", "get", "get"],
    }
    client = FakeRBACClient(
        role_bindings=[
            _role_binding("reader-one", "reader"),
            _role_binding("reader-two", "reader"),
        ],
        roles={"reader": _role("reader", [duplicate_rule, duplicate_rule])},
    )

    permissions = _details(_collect(client))["permissions"]

    assert len(permissions) == 1
    assert permissions[0]["resources"] == ["pods"]
    assert permissions[0]["verbs"] == ["get", "list"]
    assert [source["binding_name"] for source in permissions[0]["sources"]] == [
        "reader-one",
        "reader-two",
    ]
    assert client.calls.count(("read_namespaced_role", "reader", "team-a")) == 1


def test_cross_namespace_workload_is_rejected_before_api_access() -> None:
    client = FakeRBACClient()
    collector = RBACCollector(client, approved_namespace="team-a")

    with pytest.raises(PermissionError, match="not the approved namespace"):
        collector.collect(_workload(namespace="team-b"))

    assert client.calls == []
