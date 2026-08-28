"""Tests for deterministic SecurityContext analysis rules."""

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import yaml

from src.analysis.security_context_rules import (
    SecurityContextRuleEngine,
    analyze_security_context,
)
from src.collectors.security_context import collect_security_context

FIXTURES = Path(__file__).parent / "fixtures"
RISK_CONFIG = Path(__file__).parents[1] / "config" / "risk-rules.yaml"
OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as source:
        return yaml.safe_load(source)


def _fixture_evidence(name: str):
    return collect_security_context(
        _load_yaml(FIXTURES / name),
        cluster="fixture-cluster",
        observed_at=OBSERVED_AT,
    )


def test_insecure_fixture_produces_expected_confirmed_findings() -> None:
    evidence = _fixture_evidence("insecure-deployment.yaml")
    findings = analyze_security_context(evidence)

    by_factor = {finding["risk_factors"][0]: finding for finding in findings}
    assert len(findings) == 7
    assert {finding["status"] for finding in findings} == {"CONFIRMED"}
    assert {finding["risk_factors"][0] for finding in findings} == {
        "privileged_container",
        "runs_as_root",
        "allow_privilege_escalation",
        "dangerous_capability",
        "missing_seccomp_profile",
        "host_namespace_access",
    }

    config = _load_yaml(RISK_CONFIG)
    assert by_factor["privileged_container"]["score"] == config["weights"][
        "privileged_container"
    ]
    assert all(finding["score"] <= 100 for finding in findings)
    assert all(finding["evidence"] == [evidence[0].to_dict()] for finding in findings)
    assert all(finding["target"]["container"] == "api" for finding in findings)


def test_secure_fixture_has_no_confirmed_security_context_findings() -> None:
    assert analyze_security_context(_fixture_evidence("secure-deployment.yaml")) == []


def test_none_values_are_not_promoted_to_confirmed_violations() -> None:
    evidence = _fixture_evidence("secure-deployment.yaml")[0]
    for field in (
        "privileged",
        "runAsNonRoot",
        "runAsUser",
        "allowPrivilegeEscalation",
        "seccompProfile",
        "hostNetwork",
        "hostPID",
        "hostIPC",
    ):
        evidence.details[field] = None
    evidence.details["capabilities"] = {"add": None, "drop": None}

    assert analyze_security_context([evidence]) == []


def test_empty_seccomp_profile_is_a_confirmed_missing_profile() -> None:
    evidence = _fixture_evidence("secure-deployment.yaml")[0]
    evidence.details["seccompProfile"] = {}

    findings = analyze_security_context([evidence])

    assert len(findings) == 1
    assert findings[0]["risk_factors"] == ["missing_seccomp_profile"]


def test_unconfined_seccomp_profile_is_an_explicit_violation() -> None:
    evidence = _fixture_evidence("secure-deployment.yaml")[0]
    evidence.details["seccompProfile"] = {"type": "Unconfined"}

    findings = analyze_security_context([evidence])

    assert len(findings) == 1
    assert findings[0]["risk_factors"] == ["missing_seccomp_profile"]


def test_safe_added_capability_is_not_flagged() -> None:
    evidence = _fixture_evidence("secure-deployment.yaml")[0]
    evidence.details["capabilities"] = {
        "add": ["NET_BIND_SERVICE"],
        "drop": ["ALL"],
    }

    assert analyze_security_context([evidence]) == []


def test_finding_ids_and_output_are_deterministic_hex() -> None:
    evidence = _fixture_evidence("insecure-deployment.yaml")

    first = analyze_security_context(deepcopy(evidence))
    second = analyze_security_context(deepcopy(evidence))

    assert first == second
    assert all(len(finding["finding_id"]) == 16 for finding in first)
    assert all(
        set(finding["finding_id"].removeprefix("KSA-")) <= set("0123456789abcdef")
        for finding in first
    )


def test_score_is_capped_at_100_even_if_config_maximum_is_higher(tmp_path: Path) -> None:
    config = _load_yaml(RISK_CONFIG)
    config["weights"]["privileged_container"] = 150
    config["score_limits"]["maximum"] = 200
    config_path = tmp_path / "risk-rules.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    evidence = _fixture_evidence("secure-deployment.yaml")[0]
    evidence.details["privileged"] = True
    findings = SecurityContextRuleEngine(config_path=config_path).analyze([evidence])

    assert findings[0]["score"] == 100
    assert findings[0]["severity"] == "critical"
