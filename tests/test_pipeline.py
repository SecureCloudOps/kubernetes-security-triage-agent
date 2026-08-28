"""Offline integration tests for the deterministic scan pipeline."""

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

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
    assert sum(first["summary"].values()) == len(first["findings"])
    assert [finding["severity"] for finding in first["findings"]] == [
        "low",
        "low",
    ]
    assert len(runner.calls) == 2
    assert all(call[-1] == "example.invalid/secure-api:1.0.0" for call in runner.calls)
    _validate(first)


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
