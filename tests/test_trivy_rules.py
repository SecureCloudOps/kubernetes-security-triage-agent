"""Tests for deterministic Trivy vulnerability analysis rules."""

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from jsonschema import validate

from src.analysis.trivy_rules import TrivyRuleEngine, analyze_trivy
from src.collectors.trivy import EVIDENCE_SOURCE, parse_trivy_report
from src.models import Evidence, ScanResult, ScanStatus, Target

FIXTURES = Path(__file__).parent / "fixtures"
RISK_CONFIG = Path(__file__).parents[1] / "config" / "risk-rules.yaml"
FINDING_SCHEMA = Path(__file__).parents[1] / "schemas" / "finding.schema.json"
OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
IMAGE = "registry.example.com/payments/api:1.0.0"
TARGET = Target(
    cluster="test-cluster",
    namespace="team-a",
    kind="Deployment",
    name="payments",
)


def _details(name: str = "trivy-critical.json") -> dict:
    with (FIXTURES / name).open(encoding="utf-8") as source:
        return parse_trivy_report(json.load(source), image_reference=IMAGE)


def _scan(details: dict, *, status: ScanStatus = ScanStatus.COMPLETE) -> ScanResult:
    return ScanResult(
        target=TARGET,
        status=status,
        evidence=[
            Evidence(
                source=EVIDENCE_SOURCE,
                observed_at=OBSERVED_AT,
                collector_version="test-version",
                details=details,
            )
        ],
    )


def _assert_schema_valid(finding: dict) -> None:
    with FINDING_SCHEMA.open(encoding="utf-8") as source:
        validate(instance=finding, schema=json.load(source))


def test_each_unique_vulnerability_gets_trivy_severity_and_standalone_score() -> None:
    findings = analyze_trivy(_scan(_details()))

    assert len(findings) == 2
    by_cve = {
        finding["title"].split()[0]: finding for finding in findings
    }
    critical = by_cve["CVE-2025-12345"]
    high = by_cve["CVE-2025-54321"]
    assert (critical["severity"], critical["score"]) == (
        "critical",
        80,
    )
    assert (high["severity"], high["score"]) == (
        "high",
        60,
    )
    assert by_cve["CVE-2025-12345"]["risk_factors"] == ["critical_cve"]
    assert by_cve["CVE-2025-54321"]["risk_factors"] == ["high_cve"]
    assert all(finding["target"] == TARGET.to_dict() for finding in findings)
    assert all(finding["status"] == "CONFIRMED" for finding in findings)
    for finding in findings:
        _assert_schema_valid(finding)


@pytest.mark.parametrize(
    ("trivy_severity", "finding_severity", "score"),
    [
        ("CRITICAL", "critical", 80),
        ("HIGH", "high", 60),
        ("MEDIUM", "medium", 30),
        ("LOW", "low", 10),
        ("UNKNOWN", "info", 0),
    ],
)
def test_all_trivy_severity_scores_are_preserved(
    trivy_severity: str, finding_severity: str, score: int
) -> None:
    details = _details()
    vulnerability = deepcopy(details["vulnerabilities"][0])
    vulnerability["severity"] = trivy_severity
    details["vulnerabilities"] = [vulnerability]
    details["vulnerability_count"] = 1

    finding = analyze_trivy(_scan(details))[0]

    assert finding["severity"] == finding_severity
    assert finding["score"] == score
    assert finding["evidence"][0]["details"]["vulnerabilities"][0][
        "severity"
    ] == trivy_severity
    _assert_schema_valid(finding)


def test_fixed_version_is_included_only_when_trivy_reports_one() -> None:
    findings = analyze_trivy(_scan(_details()))
    by_cve = {finding["title"].split()[0]: finding for finding in findings}

    fixed = " ".join(by_cve["CVE-2025-12345"]["recommendations"])
    unfixed = " ".join(by_cve["CVE-2025-54321"]["recommendations"])
    assert "3.3.2-r0" in fixed
    assert "No fixed version is reported" in unfixed
    assert "Upgrade busybox" not in unfixed


def test_duplicate_vulnerabilities_are_deduplicated_by_required_identity() -> None:
    details = _details()
    details["vulnerabilities"].append(deepcopy(details["vulnerabilities"][0]))
    details["vulnerability_count"] += 1

    findings = analyze_trivy([_scan(details), deepcopy(_scan(details))])

    assert len(findings) == 2
    assert len({finding["finding_id"] for finding in findings}) == 2


def test_package_or_installed_version_difference_creates_distinct_finding() -> None:
    details = _details()
    variant = deepcopy(details["vulnerabilities"][0])
    variant["installed_version"] = "3.3.1-r1"
    details["vulnerabilities"].append(variant)
    details["vulnerability_count"] += 1

    findings = analyze_trivy(_scan(details))

    assert len(findings) == 3
    assert len({finding["finding_id"] for finding in findings}) == 3


def test_same_vulnerability_in_distinct_images_creates_distinct_findings() -> None:
    first = _details()
    second = deepcopy(first)
    second["image_reference"] = "registry.example.com/payments/api:1.0.1"
    scan = _scan(first)
    scan.evidence.append(
        Evidence(
            source=EVIDENCE_SOURCE,
            observed_at=OBSERVED_AT,
            collector_version="test-version",
            details=second,
        )
    )

    findings = analyze_trivy(scan)

    assert len(findings) == 4
    assert len({finding["finding_id"] for finding in findings}) == 4


def test_clean_complete_scan_creates_no_findings() -> None:
    assert analyze_trivy(_scan(_details("trivy-clean.json"))) == []


@pytest.mark.parametrize(
    "status",
    [
        ScanStatus.PARTIAL,
        ScanStatus.INSUFFICIENT_EVIDENCE,
        ScanStatus.COLLECTION_FAILED,
    ],
)
def test_failed_or_incomplete_scan_is_insufficient_evidence(status: ScanStatus) -> None:
    scan = ScanResult(
        target=TARGET,
        status=status,
        errors=["scan did not complete"],
    )

    results = analyze_trivy(scan)

    assert len(results) == 1
    assert results[0]["status"] == "INSUFFICIENT_EVIDENCE"
    assert results[0]["score"] == 0
    assert results[0]["risk_factors"] == []
    _assert_schema_valid(results[0])


def test_output_and_ids_are_deterministic() -> None:
    scan = _scan(_details())

    first = analyze_trivy(deepcopy(scan))
    second = analyze_trivy(deepcopy(scan.to_dict()))

    assert first == second
    assert all(len(finding["finding_id"]) == 16 for finding in first)
    assert all(
        set(finding["finding_id"].removeprefix("KSA-")) <= set("0123456789abcdef")
        for finding in first
    )


def test_vulnerability_scores_do_not_use_correlation_weights(tmp_path: Path) -> None:
    with RISK_CONFIG.open(encoding="utf-8") as source:
        config = yaml.safe_load(source)
    config["weights"]["critical_cve"] = 1
    config["weights"]["high_cve"] = 2
    config_path = tmp_path / "risk-rules.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    findings = TrivyRuleEngine(config_path=config_path).analyze(_scan(_details()))

    assert sorted(finding["score"] for finding in findings) == [60, 80]
    assert TrivyRuleEngine(config_path=config_path).correlation_weights == {
        "critical_cve": 1,
        "high_cve": 2,
    }


def test_incomplete_normalized_evidence_fails_closed() -> None:
    details = _details()
    details["vulnerability_count"] = 999

    results = analyze_trivy(_scan(details))

    assert len(results) == 1
    assert results[0]["status"] == "INSUFFICIENT_EVIDENCE"
    _assert_schema_valid(results[0])
