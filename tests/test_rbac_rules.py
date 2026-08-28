"""Tests for deterministic RBAC permission analysis rules."""

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import yaml
from jsonschema import validate

from src.analysis.rbac_rules import RBACRuleEngine, analyze_rbac
from src.collectors.rbac import EVIDENCE_SOURCE
from src.models import Evidence, ScanResult, ScanStatus, Target

RISK_CONFIG = Path(__file__).parents[1] / "config" / "risk-rules.yaml"
FINDING_SCHEMA = Path(__file__).parents[1] / "schemas" / "finding.schema.json"
OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _permission(
    *,
    scope: str = "namespace",
    resources: list[str],
    verbs: list[str],
    resource_names: list[str] | None = None,
    api_groups: list[str] | None = None,
    binding_kind: str | None = None,
) -> dict:
    is_cluster = scope == "cluster"
    return {
        "api_groups": api_groups if api_groups is not None else [""],
        "resources": resources,
        "verbs": verbs,
        "resource_names": resource_names or [],
        "non_resource_urls": [],
        "scope": scope,
        "namespace": None if is_cluster else "team-a",
        "sources": [
            {
                "binding_kind": binding_kind
                or ("ClusterRoleBinding" if is_cluster else "RoleBinding"),
                "binding_name": "payments-access",
                "binding_namespace": None if is_cluster else "team-a",
                "role_kind": "ClusterRole" if is_cluster else "Role",
                "role_name": "payments-role",
            }
        ],
    }


def _evidence(*permissions: dict) -> Evidence:
    return Evidence(
        source=EVIDENCE_SOURCE,
        observed_at=OBSERVED_AT,
        collector_version="test-version",
        details={
            "workload": {
                "cluster": "test-cluster",
                "namespace": "team-a",
                "kind": "Deployment",
                "name": "payments",
            },
            "service_account": {
                "name": "payments",
                "namespace": "team-a",
                "username": "system:serviceaccount:team-a:payments",
            },
            "permissions": list(permissions),
            "scope": "declared_rbac_only",
        },
    )


def _by_factor(findings: list[dict]) -> dict[str, dict]:
    return {finding["risk_factors"][0]: finding for finding in findings}


def _load_config() -> dict:
    with RISK_CONFIG.open(encoding="utf-8") as source:
        return yaml.safe_load(source)


def _assert_schema_valid(finding: dict) -> None:
    with FINDING_SCHEMA.open(encoding="utf-8") as source:
        validate(instance=finding, schema=yaml.safe_load(source))


def test_cluster_and_namespace_wildcards_are_distinct_categories() -> None:
    cluster = _permission(scope="cluster", resources=["*"], verbs=["*"])
    namespace = _permission(scope="namespace", resources=["*"], verbs=["*"])

    findings = analyze_rbac([_evidence(cluster, namespace)])
    by_factor = _by_factor(findings)

    assert "cluster_admin_binding" in by_factor
    assert "namespace_admin_permission" in by_factor
    config = _load_config()
    assert by_factor["cluster_admin_binding"]["score"] == 40
    assert by_factor["namespace_admin_permission"]["score"] == 30
    assert by_factor["cluster_admin_binding"]["score"] == config["weights"][
        "cluster_admin_binding"
    ]
    assert all(finding["status"] == "CONFIRMED" for finding in findings)
    assert all(finding["score"] <= 100 for finding in findings)


def test_secret_read_preserves_limited_resource_names_and_provenance() -> None:
    permission = _permission(
        resources=["secrets"],
        verbs=["get", "list"],
        resource_names=["database-password"],
    )

    finding = analyze_rbac([_evidence(permission)])[0]
    retained = finding["evidence"][0]["details"]["permissions"][0]

    assert finding["risk_factors"] == ["secrets_read_permission"]
    assert finding["score"] == 25
    assert retained == permission
    assert retained["resource_names"] == ["database-password"]
    assert retained["sources"][0] == permission["sources"][0]
    _assert_schema_valid(finding)


def test_escalation_verbs_and_binding_modification_share_one_category() -> None:
    direct_escalation = _permission(
        scope="cluster",
        api_groups=["rbac.authorization.k8s.io"],
        resources=["clusterroles"],
        verbs=["bind", "escalate"],
    )
    binding_changes = _permission(
        scope="cluster",
        api_groups=["rbac.authorization.k8s.io"],
        resources=["rolebindings", "clusterrolebindings"],
        verbs=["create", "patch", "update"],
    )
    impersonation = _permission(
        scope="cluster",
        api_groups=[""],
        resources=["users", "groups"],
        verbs=["impersonate"],
    )

    findings = analyze_rbac(
        [_evidence(direct_escalation, binding_changes, impersonation)]
    )

    assert len(findings) == 1
    assert findings[0]["risk_factors"] == ["rbac_escalation_permission"]
    assert findings[0]["score"] == 35
    assert findings[0]["evidence"][0]["details"]["permissions"] == [
        direct_escalation,
        binding_changes,
        impersonation,
    ]


def test_create_on_pods_exec_is_detected_but_pod_create_is_not() -> None:
    exec_permission = _permission(resources=["pods/exec"], verbs=["create"])
    ordinary_pod_create = _permission(resources=["pods"], verbs=["create"])

    findings = analyze_rbac([_evidence(exec_permission, ordinary_pod_create)])

    assert len(findings) == 1
    assert findings[0]["risk_factors"] == ["pod_exec_permission"]
    assert findings[0]["score"] == 20


def test_duplicate_rules_and_evidence_create_one_finding_per_category() -> None:
    permission = _permission(
        resources=["secrets"], verbs=["get"], resource_names=["one-secret"]
    )
    evidence = _evidence(permission, deepcopy(permission))

    findings = analyze_rbac([evidence, deepcopy(evidence)])

    assert len(findings) == 1
    assert findings[0]["risk_factors"] == ["secrets_read_permission"]
    assert findings[0]["evidence"] == [evidence.to_dict()]


def test_ordinary_read_only_workload_permissions_create_no_findings() -> None:
    evidence = _evidence(
        _permission(
            api_groups=["apps"],
            resources=["deployments", "replicasets"],
            verbs=["get", "list", "watch"],
        ),
        _permission(resources=["pods", "configmaps"], verbs=["get", "list"]),
    )

    assert analyze_rbac([evidence]) == []


def test_collection_failure_creates_zero_score_insufficient_evidence() -> None:
    failed = ScanResult(
        target=Target(
            cluster="test-cluster",
            namespace="team-a",
            kind="Deployment",
            name="payments",
        ),
        status=ScanStatus.COLLECTION_FAILED,
        errors=["RBAC API unavailable"],
    )

    result = analyze_rbac(failed)[0]

    assert result["status"] == "INSUFFICIENT_EVIDENCE"
    assert result["score"] == 0
    assert result["risk_factors"] == []
    assert result["evidence"][0]["details"]["collection_status"] == (
        "COLLECTION_FAILED"
    )
    assert analyze_rbac(failed.to_dict()) == [result]
    _assert_schema_valid(result)


def test_finding_ids_and_output_are_deterministic_hex() -> None:
    evidence = _evidence(_permission(resources=["pods/exec"], verbs=["create"]))

    first = analyze_rbac(deepcopy([evidence]))
    second = analyze_rbac(deepcopy([evidence]))

    assert first == second
    assert len(first[0]["finding_id"]) == 16
    assert set(first[0]["finding_id"].removeprefix("KSA-")) <= set(
        "0123456789abcdef"
    )


def test_custom_config_controls_each_rbac_score(tmp_path: Path) -> None:
    config = _load_config()
    config["weights"].update(
        {
            "cluster_admin_binding": 41,
            "namespace_admin_permission": 31,
            "secrets_read_permission": 26,
            "rbac_escalation_permission": 36,
            "pod_exec_permission": 21,
        }
    )
    config_path = tmp_path / "risk-rules.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    engine = RBACRuleEngine(config_path=config_path)
    evidence = _evidence(
        _permission(scope="cluster", resources=["*"], verbs=["*"])
    )

    scores = {
        finding["risk_factors"][0]: finding["score"]
        for finding in engine.analyze([evidence])
    }
    assert scores == {
        "cluster_admin_binding": 41,
        "pod_exec_permission": 21,
        "rbac_escalation_permission": 36,
        "secrets_read_permission": 26,
    }
