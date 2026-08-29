"""Tests for bounded, shell-free Trivy image collection."""

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, call, patch

import pytest

from src.collectors.trivy import TrivyImageCollector
from src.models import ScanStatus, Target

FIXTURES = Path(__file__).parent / "fixtures"
OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
TARGET = Target(
    cluster="test-cluster",
    namespace="team-a",
    kind="Deployment",
    name="payments",
)


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _completed(stdout: str, *, returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


@patch("src.collectors.trivy.subprocess.run")
def test_critical_report_is_normalized_and_unfixed_vulnerability_is_kept(
    run: Mock,
) -> None:
    run.return_value = _completed(_fixture("trivy-critical.json"))
    image = "registry.example.com/payments/api:1.0.0"

    result = TrivyImageCollector(collector_version="test-version").collect(
        [{"name": "api", "type": "container", "image": image}],
        target=TARGET,
        observed_at=OBSERVED_AT,
    )

    assert result.status is ScanStatus.COMPLETE
    assert result.errors == []
    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.source == "trivy"
    assert evidence.collector_version == "test-version"
    assert evidence.observed_at == OBSERVED_AT
    assert evidence.details == {
        "image_reference": image,
        "image_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "trivy_version": "0.70.0",
        "vulnerability_count": 2,
        "vulnerabilities": [
            {
                "vulnerability_id": "CVE-2025-12345",
                "severity": "CRITICAL",
                "package_name": "libcrypto3",
                "installed_version": "3.3.1-r0",
                "fixed_version": "3.3.2-r0",
                "title": "OpenSSL certificate validation issue",
                "reference": "https://avd.aquasec.com/nvd/cve-2025-12345",
            },
            {
                "vulnerability_id": "CVE-2025-54321",
                "severity": "HIGH",
                "package_name": "busybox",
                "installed_version": "1.36.1-r29",
                "fixed_version": None,
                "title": "BusyBox archive extraction issue",
                "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-54321",
            },
        ],
        "containers": [{"name": "api", "type": "container"}],
    }
    run.assert_called_once_with(
        [
            "trivy",
            "image",
            "--quiet",
            "--format",
            "json",
            "--scanners",
            "vuln",
            image,
        ],
        shell=False,
        timeout=300,
        capture_output=True,
        text=True,
    )


@patch("src.collectors.trivy.subprocess.run")
def test_severity_filter_is_validated_and_forwarded_to_trivy(run: Mock) -> None:
    run.return_value = _completed(_fixture("trivy-clean.json"))
    image = "registry.example.com/payments/api:2.0.0"

    result = TrivyImageCollector(
        severities="critical, HIGH,critical"
    ).collect([image], target=TARGET)

    assert result.status is ScanStatus.COMPLETE
    command = run.call_args.args[0]
    assert command[-3:] == ["--severity", "CRITICAL,HIGH", image]


@pytest.mark.parametrize(
    "severities",
    ["SEVERE", "HIGH,", "HIGH,--input=report.json", [], ["HIGH", 1]],
)
@patch("src.collectors.trivy.subprocess.run")
def test_invalid_severity_filters_never_reach_trivy(
    run: Mock, severities: object
) -> None:
    with pytest.raises((TypeError, ValueError), match="severity|severities"):
        TrivyImageCollector(severities=severities)

    run.assert_not_called()


@patch("src.collectors.trivy.subprocess.run")
def test_clean_report_is_successful_evidence_with_zero_vulnerabilities(
    run: Mock,
) -> None:
    run.return_value = _completed(_fixture("trivy-clean.json"))

    result = TrivyImageCollector().collect(
        ["registry.example.com/payments/api:2.0.0"], target=TARGET
    )

    assert result.status is ScanStatus.COMPLETE
    assert len(result.evidence) == 1
    assert result.evidence[0].details["vulnerability_count"] == 0


@patch("src.collectors.trivy.subprocess.run")
def test_successful_filtered_report_without_results_is_clean(run: Mock) -> None:
    image = "busybox:1.37.0"
    run.return_value = _completed(
        json.dumps(
            {
                "SchemaVersion": 2,
                "ArtifactID": "sha256:abc",
                "ArtifactName": image,
                "ArtifactType": "container_image",
                "Metadata": {"RepoDigests": ["busybox@sha256:def"]},
            }
        )
    )

    result = TrivyImageCollector(severities="CRITICAL,HIGH").collect(
        [image], target=TARGET
    )

    assert result.status is ScanStatus.COMPLETE
    assert result.evidence[0].details["vulnerability_count"] == 0
    assert result.evidence[0].details["vulnerabilities"] == []


@patch("src.collectors.trivy.subprocess.run")
def test_duplicate_images_are_scanned_once_and_container_context_is_combined(
    run: Mock,
) -> None:
    run.return_value = _completed(_fixture("trivy-clean.json"))
    image = "registry.example.com/payments/api:2.0.0"

    result = TrivyImageCollector().collect(
        [
            {"name": "api", "type": "container", "image": image},
            {"name": "migrate", "type": "initContainer", "image": image},
            image,
        ],
        target=TARGET,
    )

    assert result.status is ScanStatus.COMPLETE
    assert run.call_count == 1
    assert result.evidence[0].details["containers"] == [
        {"name": "api", "type": "container"},
        {"name": "migrate", "type": "initContainer"},
    ]


@pytest.mark.parametrize(
    "unsafe_image",
    ["--input=commands.txt", "-", "image:tag\n--server=evil", "image:\x00tag"],
)
@patch("src.collectors.trivy.subprocess.run")
def test_unsafe_images_never_reach_subprocess(run: Mock, unsafe_image: str) -> None:
    with pytest.raises(ValueError, match="image"):
        TrivyImageCollector().collect(
            ["safe.example/api:1", unsafe_image], target=TARGET
        )

    run.assert_not_called()


@patch("src.collectors.trivy.subprocess.run")
def test_maximum_is_enforced_before_any_subprocess(run: Mock) -> None:
    with pytest.raises(ValueError, match="exceeds maximum 2"):
        TrivyImageCollector(max_images=2).collect(
            ["example/a:1", "example/b:1", "example/c:1"], target=TARGET
        )

    run.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [
        FileNotFoundError("trivy was not found"),
        subprocess.TimeoutExpired(cmd=["trivy", "image"], timeout=300),
    ],
)
@patch("src.collectors.trivy.subprocess.run")
def test_missing_or_timed_out_trivy_returns_collection_failed(
    run: Mock, failure: Exception
) -> None:
    run.side_effect = failure

    result = TrivyImageCollector().collect(["example/api:1"], target=TARGET)

    assert result.status is ScanStatus.COLLECTION_FAILED
    assert result.evidence == []
    assert result.errors


@pytest.mark.parametrize(
    "completed",
    [
        _completed("not json"),
        _completed(json.dumps({"SchemaVersion": 2})),
        _completed("", returncode=1, stderr="database download failed"),
    ],
)
@patch("src.collectors.trivy.subprocess.run")
def test_invalid_json_invalid_report_or_failed_trivy_returns_collection_failed(
    run: Mock, completed: subprocess.CompletedProcess
) -> None:
    run.return_value = completed

    result = TrivyImageCollector().collect(["example/api:1"], target=TARGET)

    assert result.status is ScanStatus.COLLECTION_FAILED
    assert result.evidence == []
    assert result.errors


@patch("src.collectors.trivy.subprocess.run")
def test_each_distinct_image_uses_the_same_fixed_command(run: Mock) -> None:
    run.side_effect = [
        _completed(_fixture("trivy-clean.json")),
        _completed(_fixture("trivy-clean.json")),
    ]

    result = TrivyImageCollector().collect(
        ["example/api:1", "example/worker:1"], target=TARGET
    )

    assert result.status is ScanStatus.COMPLETE
    assert run.call_args_list == [
        call(
            [
                "trivy",
                "image",
                "--quiet",
                "--format",
                "json",
                "--scanners",
                "vuln",
                image,
            ],
            shell=False,
            timeout=300,
            capture_output=True,
            text=True,
        )
        for image in ("example/api:1", "example/worker:1")
    ]
