"""Tests for deterministic workload exposure analysis rules."""

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import yaml
from jsonschema import validate

from src.analysis.exposure_rules import ExposureRuleEngine, analyze_exposure
from src.collectors.exposure import EVIDENCE_SOURCE
from src.models import Evidence

RISK_CONFIG = Path(__file__).parents[1] / "config" / "risk-rules.yaml"
FINDING_SCHEMA = Path(__file__).parents[1] / "schemas" / "finding.schema.json"
OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _evidence(
    classification: str,
    *,
    services: list[dict] | None = None,
    ingresses: list[dict] | None = None,
) -> Evidence:
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
                "podLabels": {"app": "payments"},
            },
            "classification": classification,
            "conclusion": "fixture conclusion",
            "services": services or [],
            "ingresses": ingresses or [],
        },
    )


def _load_config() -> dict:
    with RISK_CONFIG.open(encoding="utf-8") as source:
        return yaml.safe_load(source)


def _assert_schema_valid(result: dict) -> None:
    with FINDING_SCHEMA.open(encoding="utf-8") as source:
        validate(instance=result, schema=yaml.safe_load(source))


def test_confirmed_external_creates_public_exposure_finding() -> None:
    evidence = _evidence(
        "confirmed_external",
        services=[
            {
                "name": "payments-public",
                "type": "LoadBalancer",
                "loadBalancerIngress": [{"ip": "34.120.10.20"}],
                "classification": "confirmed_external",
            }
        ],
        ingresses=[
            {
                "name": "payments",
                "hosts": ["pay.example.com"],
                "classification": "confirmed_external",
            }
        ],
    )

    findings = analyze_exposure([evidence])

    assert len(findings) == 1
    assert findings[0]["status"] == "CONFIRMED"
    assert findings[0]["risk_factors"] == ["public_exposure"]
    assert findings[0]["score"] == _load_config()["weights"]["public_exposure"]
    assert findings[0]["evidence"] == [evidence.to_dict()]
    _assert_schema_valid(findings[0])


def test_potentially_external_is_lower_scored_and_never_claims_confirmation() -> None:
    evidence = _evidence(
        "potentially_external",
        services=[{"name": "payments-node", "type": "NodePort"}],
        ingresses=[{"name": "payments", "loadBalancerIngress": []}],
    )

    findings = analyze_exposure([evidence])

    assert len(findings) == 1
    finding = findings[0]
    config = _load_config()
    # CONFIRMED means the deterministic rule confirmed the limited
    # potentially-external state, not that public reachability was confirmed.
    assert finding["status"] == "CONFIRMED"
    assert finding["risk_factors"] == ["potential_external_exposure"]
    assert finding["score"] == config["weights"]["potential_external_exposure"]
    assert finding["score"] < config["weights"]["public_exposure"]
    narrative = " ".join(
        [finding["title"], *finding["recommendations"], *finding["limitations"]]
    ).lower()
    assert "confirmed public" not in narrative
    assert "not confirmed" in narrative
    _assert_schema_valid(finding)


def test_unknown_creates_zero_score_insufficient_evidence_result() -> None:
    evidence = _evidence("unknown")

    results = analyze_exposure([evidence])

    assert len(results) == 1
    assert results[0]["status"] == "INSUFFICIENT_EVIDENCE"
    assert results[0]["score"] == 0
    assert results[0]["risk_factors"] == []
    assert results[0]["evidence"] == [evidence.to_dict()]
    _assert_schema_valid(results[0])


def test_internal_creates_no_exposure_finding() -> None:
    assert analyze_exposure([_evidence("internal")]) == []


def test_multiple_resources_and_repeated_workload_evidence_score_only_once() -> None:
    first = _evidence(
        "potentially_external",
        services=[{"name": "payments-node", "type": "NodePort"}],
    )
    second = _evidence(
        "confirmed_external",
        services=[{"name": "payments-lb", "type": "LoadBalancer"}],
        ingresses=[{"name": "payments", "host": "pay.example.com"}],
    )

    findings = analyze_exposure([first, second, deepcopy(second)])

    assert len(findings) == 1
    assert findings[0]["risk_factors"] == ["public_exposure"]
    assert findings[0]["score"] == _load_config()["weights"]["public_exposure"]
    assert len(findings[0]["evidence"]) == 2
    evidence_details = [item["details"] for item in findings[0]["evidence"]]
    assert {item["classification"] for item in evidence_details} == {
        "potentially_external",
        "confirmed_external",
    }
    assert {
        service["name"]
        for item in evidence_details
        for service in item["services"]
    } == {"payments-node", "payments-lb"}


def test_finding_id_and_output_are_deterministic_hex() -> None:
    evidence = _evidence("confirmed_external")

    first = analyze_exposure(deepcopy([evidence]))
    second = analyze_exposure(deepcopy([evidence]))

    assert first == second
    finding_id = first[0]["finding_id"]
    assert len(finding_id) == 16
    assert set(finding_id.removeprefix("KSA-")) <= set("0123456789abcdef")


def test_custom_config_controls_both_exposure_scores(tmp_path: Path) -> None:
    config = _load_config()
    config["weights"]["public_exposure"] = 41
    config["weights"]["potential_external_exposure"] = 7
    config_path = tmp_path / "risk-rules.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    engine = ExposureRuleEngine(config_path=config_path)

    assert engine.analyze([_evidence("confirmed_external")])[0]["score"] == 41
    assert engine.analyze([_evidence("potentially_external")])[0]["score"] == 7
