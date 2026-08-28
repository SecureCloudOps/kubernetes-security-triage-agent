"""Offline integration tests for the deterministic scan pipeline."""

import json
import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from src.pipeline import DeterministicScanPipeline, WorkloadCollectionError

FIXTURES = Path(__file__).parent / "fixtures"
REPORT_SCHEMA = Path(__file__).parents[1] / "schemas" / "scan-report.schema.json"
OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
TARGET = {
    "cluster": "test-cluster",
    "namespace": "production",
    "kind": "Deployment",
    "name": "secure-api",
}


def _workload() -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "secure-api", "namespace": "production"},
        "spec": {
            "template": {
                "metadata": {"labels": {"app": "secure-api"}},
                "spec": {
                    "serviceAccountName": "secure-api",
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "api",
                            "image": "example.invalid/secure-api:1.0.0",
                            "securityContext": {
                                "privileged": False,
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"add": [], "drop": ["ALL"]},
                            },
                        }
                    ],
                },
            }
        },
    }


class OfflineKubernetesClient:
    def __init__(
        self,
        *,
        workload_error: Exception | None = None,
        exposure_error: Exception | None = None,
    ) -> None:
        self.workload_error = workload_error
        self.exposure_error = exposure_error
        self.calls: list[str] = []

    def read_namespaced_deployment(self, *, name: str, namespace: str) -> dict:
        self.calls.append("workload")
        if self.workload_error:
            raise self.workload_error
        return _workload()

    def list_namespaced_service(self, *, namespace: str) -> dict:
        self.calls.append("services")
        if self.exposure_error:
            raise self.exposure_error
        return {"items": []}

    def list_namespaced_ingress(self, *, namespace: str) -> dict:
        self.calls.append("ingresses")
        return {"items": []}

    def list_namespaced_network_policy(self, *, namespace: str) -> dict:
        self.calls.append("network_policies")
        return {"items": []}

    def list_namespaced_role_binding(self, *, namespace: str) -> dict:
        self.calls.append("role_bindings")
        return {"items": []}

    def list_cluster_role_binding(self) -> dict:
        self.calls.append("cluster_role_bindings")
        return {"items": []}


class OfflineTrivyRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str], **kwargs):
        self.calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            (FIXTURES / "trivy-clean.json").read_text(encoding="utf-8"),
            "",
        )


def _pipeline(
    client: OfflineKubernetesClient,
    runner: OfflineTrivyRunner,
    **kwargs,
) -> DeterministicScanPipeline:
    return DeterministicScanPipeline(
        client,
        approved_namespace="production",
        trivy_process_runner=runner,
        **kwargs,
    )


def _validate(report: dict) -> None:
    schema = json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(
        schema, format_checker=FormatChecker()
    ).validate(report)


def test_one_call_returns_a_schema_valid_deterministic_complete_report() -> None:
    client = OfflineKubernetesClient()
    runner = OfflineTrivyRunner()
    pipeline = _pipeline(client, runner)

    first = pipeline.run(TARGET, observed_at=OBSERVED_AT)
    second = pipeline.run(TARGET, observed_at=OBSERVED_AT)

    assert first == second
    assert first["scan_status"] == "COMPLETE"
    assert set(first["collector_status"].values()) == {"COMPLETE"}
    assert set(first["analyzer_status"].values()) == {"COMPLETE"}
    assert first["evidence_gaps"] == []
    assert first["attack_paths"] == []
    assert first["ai_status"] == "DISABLED"
    assert first["ai_analysis"] is None
    assert sum(first["summary"].values()) == len(first["findings"])
    assert [finding["severity"] for finding in first["findings"]] == [
        "low",
        "low",
    ]
    assert len(runner.calls) == 2
    assert all(call[-1] == "example.invalid/secure-api:1.0.0" for call in runner.calls)
    _validate(first)


def test_optional_ai_success_adds_only_validated_interpretation() -> None:
    analyst = Mock()

    def analyze(report: dict, attack_paths: list[dict]) -> dict:
        finding_id = report["findings"][0]["finding_id"]
        return {
            "status": "COMPLETE",
            "analysis": {
                "executive_summary": "Review the confirmed deterministic finding.",
                "attack_path_explanations": [],
                "priority_order": [
                    {
                        "position": 1,
                        "reference_type": "finding",
                        "reference_id": finding_id,
                        "rationale": "It is the highest available confirmed signal.",
                    }
                ],
                "remediation_steps": [
                    {
                        "finding_ids": [finding_id],
                        "attack_path_ids": [],
                        "step": "Review and remediate the referenced finding.",
                    }
                ],
                "operator_review_notes": [
                    {
                        "finding_ids": [finding_id],
                        "attack_path_ids": [],
                        "note": "Confirm the configuration is intentional.",
                    }
                ],
                "limitations": ["This interpretation is not collected evidence."],
            },
        }

    analyst.analyze.side_effect = analyze
    report = _pipeline(
        OfflineKubernetesClient(),
        OfflineTrivyRunner(),
        ai_analyst=analyst,
    ).run(TARGET, observed_at=OBSERVED_AT, ai_enabled=True)

    assert report["ai_status"] == "SUCCESS"
    assert report["ai_analysis"]["executive_summary"].startswith("Review")
    analyst.analyze.assert_called_once()
    _validate(report)


def test_correlation_precedes_ai_and_skipped_analysis_remains_null() -> None:
    correlator = Mock()

    def correlate(report: dict) -> list[dict]:
        finding_id = report["findings"][0]["finding_id"]
        return [
            {
                "attack_path_id": "KAP-0123456789ab",
                "status": "PLAUSIBLE",
                "title": "Mocked deterministic correlation",
                "score": 55,
                "severity": "high",
                "supporting_finding_ids": [finding_id],
                "risk_factors": ["public_exposure", "missing_network_policy"],
                "explanation": "Two deterministic signals form a hypothesis.",
                "limitations": ["This does not establish exploitation."],
            }
        ]

    correlator.correlate.side_effect = correlate
    analyst = Mock()

    def skip(report: dict, attack_paths: list[dict]) -> dict:
        assert report["attack_paths"] == attack_paths
        assert attack_paths[0]["status"] == "PLAUSIBLE"
        return {"status": "SKIPPED", "analysis": None}

    analyst.analyze.side_effect = skip
    report = _pipeline(
        OfflineKubernetesClient(),
        OfflineTrivyRunner(),
        correlator=correlator,
        ai_analyst=analyst,
    ).run(TARGET, observed_at=OBSERVED_AT, ai_enabled=True)

    assert len(report["attack_paths"]) == 1
    assert report["ai_status"] == "SKIPPED"
    assert report["ai_analysis"] is None
    correlator.correlate.assert_called_once()
    analyst.analyze.assert_called_once()
    _validate(report)


def test_ai_failure_preserves_all_deterministic_results() -> None:
    baseline = _pipeline(
        OfflineKubernetesClient(), OfflineTrivyRunner()
    ).run(TARGET, observed_at=OBSERVED_AT)
    analyst = Mock()

    def fail_after_mutation(report: dict, attack_paths: list[dict]) -> dict:
        report["findings"].clear()
        attack_paths.clear()
        raise RuntimeError("mocked OpenAI failure")

    analyst.analyze.side_effect = fail_after_mutation
    failed = _pipeline(
        OfflineKubernetesClient(),
        OfflineTrivyRunner(),
        ai_analyst=analyst,
    ).run(TARGET, observed_at=OBSERVED_AT, ai_enabled=True)

    deterministic_fields = (
        "scan_status",
        "target",
        "collector_status",
        "analyzer_status",
        "findings",
        "attack_paths",
        "evidence_gaps",
        "summary",
    )
    assert {key: failed[key] for key in deterministic_fields} == {
        key: deepcopy(baseline[key]) for key in deterministic_fields
    }
    assert failed["ai_status"] == "FAILED"
    assert failed["ai_analysis"] is None
    _validate(failed)


def test_secondary_collector_failure_is_partial_and_creates_an_evidence_gap() -> None:
    client = OfflineKubernetesClient(exposure_error=OSError("API unavailable"))
    report = _pipeline(client, OfflineTrivyRunner()).run(
        TARGET, observed_at=OBSERVED_AT
    )

    assert report["scan_status"] == "PARTIAL"
    assert report["collector_status"]["exposure"] == "COLLECTION_FAILED"
    assert {
        (gap["stage"], gap["component"], gap["status"])
        for gap in report["evidence_gaps"]
    } == {("COLLECTION", "exposure", "COLLECTION_FAILED")}
    assert report["analyzer_status"]["exposure"] == "COMPLETE"
    _validate(report)


def test_workload_collection_failure_stops_before_secondary_collectors() -> None:
    client = OfflineKubernetesClient(workload_error=LookupError("not found"))
    runner = OfflineTrivyRunner()

    with pytest.raises(WorkloadCollectionError, match="not found"):
        _pipeline(client, runner).run(TARGET, observed_at=OBSERVED_AT)

    assert client.calls == ["workload"]
    assert runner.calls == []


def test_analyzer_failure_marks_only_its_section_and_report_partial() -> None:
    def fail_exposure(_evidence):
        raise RuntimeError("broken rule configuration")

    report = _pipeline(
        OfflineKubernetesClient(),
        OfflineTrivyRunner(),
        analyzers={"exposure": fail_exposure},
    ).run(TARGET, observed_at=OBSERVED_AT)

    assert report["scan_status"] == "PARTIAL"
    assert report["analyzer_status"]["exposure"] == "ANALYSIS_FAILED"
    assert all(
        status == "COMPLETE"
        for name, status in report["analyzer_status"].items()
        if name != "exposure"
    )
    assert any(
        gap["stage"] == "ANALYSIS"
        and gap["component"] == "exposure"
        and gap["status"] == "ANALYSIS_FAILED"
        for gap in report["evidence_gaps"]
    )
    _validate(report)


def test_invalid_target_is_rejected_before_any_dependency_is_called() -> None:
    client = OfflineKubernetesClient()
    runner = OfflineTrivyRunner()

    with pytest.raises(ValueError, match="unsupported workload kind"):
        _pipeline(client, runner).run(
            {**TARGET, "kind": "Secret"}, observed_at=OBSERVED_AT
        )

    assert client.calls == []
    assert runner.calls == []
