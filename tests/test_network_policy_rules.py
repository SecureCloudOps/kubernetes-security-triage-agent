"""Tests for deterministic NetworkPolicy isolation analysis rules."""

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import yaml
from jsonschema import validate

from src.analysis.network_policy_rules import (
    NetworkPolicyRuleEngine,
    analyze_network_policy,
)
from src.collectors.network_policy import EVIDENCE_SOURCE
from src.models import Evidence, ScanResult, ScanStatus, Target

RISK_CONFIG = Path(__file__).parents[1] / "config" / "risk-rules.yaml"
FINDING_SCHEMA = Path(__file__).parents[1] / "schemas" / "finding.schema.json"
OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _evidence(
    ingress_isolated: bool | None,
    egress_isolated: bool | None,
    *,
    policies: list[dict] | None = None,
) -> Evidence:
    policy_evidence = policies or []
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
                "pod_labels": {"app": "payments"},
            },
            "ingress_isolated": ingress_isolated,
            "egress_isolated": egress_isolated,
            "matching_policies": [policy["name"] for policy in policy_evidence],
            "policies": policy_evidence,
            "scope": "declared_configuration_only",
            "enforcement": "not_assessed",
        },
    )


def _policy(name: str, *policy_types: str) -> dict:
    return {
        "name": name,
        "policy_types": list(policy_types),
        "pod_selector": {"matchLabels": {"app": "payments"}},
        "ingress": [],
        "egress": [],
    }


def _load_config() -> dict:
    with RISK_CONFIG.open(encoding="utf-8") as source:
        return yaml.safe_load(source)


def _assert_schema_valid(result: dict) -> None:
    with FINDING_SCHEMA.open(encoding="utf-8") as source:
        validate(instance=result, schema=yaml.safe_load(source))


def test_no_matching_policy_creates_only_missing_network_policy() -> None:
    evidence = _evidence(False, False)

    findings = analyze_network_policy([evidence, deepcopy(evidence)])

    assert len(findings) == 1
    assert findings[0]["risk_factors"] == ["missing_network_policy"]
    assert findings[0]["score"] == _load_config()["weights"][
        "missing_network_policy"
    ]
    assert findings[0]["evidence"] == [evidence.to_dict()]
    _assert_schema_valid(findings[0])


def test_ingress_only_creates_missing_egress_isolation() -> None:
    policy = _policy("deny-ingress", "Ingress")
    evidence = _evidence(True, False, policies=[policy])

    findings = analyze_network_policy([evidence])

    assert len(findings) == 1
    assert findings[0]["risk_factors"] == ["missing_egress_isolation"]
    assert findings[0]["score"] == 10
    assert findings[0]["evidence"][0]["details"]["policies"] == [policy]
    _assert_schema_valid(findings[0])


def test_egress_only_creates_missing_ingress_isolation() -> None:
    policy = _policy("deny-egress", "Egress")
    evidence = _evidence(False, True, policies=[policy])

    findings = analyze_network_policy([evidence])

    assert len(findings) == 1
    assert findings[0]["risk_factors"] == ["missing_ingress_isolation"]
    assert findings[0]["score"] == 10
    _assert_schema_valid(findings[0])


def test_both_directions_isolated_creates_no_finding() -> None:
    evidence = _evidence(
        True,
        True,
        policies=[_policy("deny-all", "Ingress", "Egress")],
    )

    assert analyze_network_policy([evidence]) == []


def test_unknown_evidence_creates_zero_score_insufficient_result() -> None:
    evidence = _evidence(None, None)

    results = analyze_network_policy([evidence])

    assert len(results) == 1
    assert results[0]["status"] == "INSUFFICIENT_EVIDENCE"
    assert results[0]["score"] == 0
    assert results[0]["risk_factors"] == []
    assert results[0]["evidence"] == [evidence.to_dict()]
    _assert_schema_valid(results[0])


def test_collection_failure_creates_zero_score_insufficient_result() -> None:
    failed = ScanResult(
        target=Target(
            cluster="test-cluster",
            namespace="team-a",
            kind="Deployment",
            name="payments",
        ),
        status=ScanStatus.COLLECTION_FAILED,
        errors=["networking API unavailable"],
    )

    results = analyze_network_policy(failed)

    assert len(results) == 1
    assert results[0]["status"] == "INSUFFICIENT_EVIDENCE"
    assert results[0]["score"] == 0
    assert results[0]["evidence"][0]["details"]["collection_status"] == (
        "COLLECTION_FAILED"
    )
    _assert_schema_valid(results[0])


def test_serialized_collection_failure_is_also_fail_closed() -> None:
    failed = ScanResult(
        target=Target(
            cluster="test-cluster",
            namespace="team-a",
            kind="Deployment",
            name="payments",
        ),
        status=ScanStatus.COLLECTION_FAILED,
        errors=["networking API unavailable"],
    )

    result = analyze_network_policy(failed.to_dict())[0]

    assert result["status"] == "INSUFFICIENT_EVIDENCE"
    assert result["score"] == 0


def test_ids_and_output_are_deterministic_and_limitations_are_precise() -> None:
    evidence = _evidence(
        True,
        False,
        policies=[_policy("allow-web", "Ingress")],
    )

    first = analyze_network_policy(deepcopy([evidence]))
    second = analyze_network_policy(deepcopy([evidence]))

    assert first == second
    finding_id = first[0]["finding_id"]
    assert len(finding_id) == 16
    assert set(finding_id.removeprefix("KSA-")) <= set("0123456789abcdef")
    limitations = " ".join(first[0]["limitations"]).lower()
    assert "runtime cni enforcement was not verified" in limitations
    assert "does not prove" in limitations
    assert "restrictive" in limitations


def test_custom_config_controls_each_network_policy_score(tmp_path: Path) -> None:
    config = _load_config()
    config["weights"].update(
        {
            "missing_network_policy": 11,
            "missing_ingress_isolation": 12,
            "missing_egress_isolation": 13,
        }
    )
    config_path = tmp_path / "risk-rules.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    engine = NetworkPolicyRuleEngine(config_path=config_path)

    assert engine.analyze([_evidence(False, False)])[0]["score"] == 11
    assert (
        engine.analyze(
            [_evidence(False, True, policies=[_policy("egress", "Egress")])]
        )[0]["score"]
        == 12
    )
    assert (
        engine.analyze(
            [_evidence(True, False, policies=[_policy("ingress", "Ingress")])]
        )[0]["score"]
        == 13
    )
