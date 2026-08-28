"""Offline tests for the scan command and its exit behavior."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src import cli


def _report(*, status: str = "COMPLETE", severity: str = "high") -> dict:
    target = {
        "cluster": "test-cluster",
        "namespace": "demo",
        "kind": "Deployment",
        "name": "vulnerable-api",
        "container": None,
    }
    collector_status = {
        "workload": "COMPLETE",
        "security_context": "COMPLETE",
        "exposure": "COMPLETE",
        "network_policy": "COMPLETE",
        "rbac": "COMPLETE",
        "trivy": "COMPLETE",
    }
    gaps = []
    if status == "PARTIAL":
        collector_status["trivy"] = "COLLECTION_FAILED"
        gaps = [
            {
                "component": "trivy",
                "stage": "COLLECTION",
                "status": "COLLECTION_FAILED",
                "errors": ["mocked Trivy failure"],
            }
        ]
    finding = {
        "finding_id": "KSA-0123456789ab",
        "title": "Test finding",
        "status": "CONFIRMED",
        "severity": severity,
        "score": 70,
        "confidence": "high",
        "target": target,
        "evidence": [
            {
                "source": "mocked.trivy",
                "observed_at": "2026-01-02T03:04:05Z",
                "collector_version": "mocked",
                "details": {"image_reference": "example.invalid/api:1"},
            }
        ],
        "risk_factors": ["test"],
        "attack_path": None,
        "blast_radius": None,
        "recommendations": ["Apply the tested remediation."],
        "limitations": ["No exploitation was tested."],
    }
    summary = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    summary[severity] = 1
    return {
        "scan_status": status,
        "target": target,
        "collector_status": collector_status,
        "analyzer_status": {
            "security_context": "COMPLETE",
            "exposure": "COMPLETE",
            "network_policy": "COMPLETE",
            "rbac": "COMPLETE",
            "trivy": "COMPLETE",
        },
        "findings": [finding],
        "evidence_gaps": gaps,
        "summary": summary,
    }


def _run_with_mocks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    report: dict,
    *,
    fail_on: str = "none",
) -> tuple[int, Mock]:
    kubernetes_clients = {
        "core": Mock(name="CoreV1Api"),
        "apps": Mock(name="AppsV1Api"),
        "networking": Mock(name="NetworkingV1Api"),
        "rbac": Mock(name="RbacAuthorizationV1Api"),
    }
    load_context = Mock(return_value=("test-cluster", kubernetes_clients))
    monkeypatch.setattr(cli, "load_current_context", load_context)

    # The mocked pipeline is the unit-test seam for both Kubernetes collection
    # and the Trivy subprocess dependency; neither external system is contacted.
    pipeline = Mock()
    pipeline.run.return_value = report
    pipeline_factory = Mock(return_value=pipeline)
    monkeypatch.setattr(cli, "DeterministicScanPipeline", pipeline_factory)

    code = cli.main(
        [
            "scan",
            "--namespace",
            "demo",
            "--kind",
            "Deployment",
            "--name",
            "vulnerable-api",
            "--allowed-namespace",
            "demo",
            "--output-dir",
            str(tmp_path),
            "--fail-on",
            fail_on,
        ]
    )
    return code, pipeline


def test_scan_writes_matching_valid_json_and_markdown_with_mocked_dependencies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, pipeline = _run_with_mocks(monkeypatch, tmp_path, _report())

    assert code == cli.EXIT_OK
    pipeline.run.assert_called_once_with(
        {
            "cluster": "test-cluster",
            "namespace": "demo",
            "kind": "Deployment",
            "name": "vulnerable-api",
        }
    )
    written = json.loads((tmp_path / "scan-report.json").read_text(encoding="utf-8"))
    markdown = (tmp_path / "scan-report.md").read_text(encoding="utf-8")
    assert written["target"]["name"] == "vulnerable-api"
    assert written["summary"]["high"] == 1
    assert "vulnerable-api" in markdown
    assert "| 0 | 1 | 0 | 0 | 0 |" in markdown


def test_command_integration_mocks_kubernetes_apis_and_trivy_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workload = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "vulnerable-api", "namespace": "demo"},
        "spec": {
            "template": {
                "metadata": {"labels": {"app": "vulnerable-api"}},
                "spec": {
                    "serviceAccountName": "default",
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "api",
                            "image": "example.invalid/api:1",
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
    core = SimpleNamespace(
        list_namespaced_service=Mock(return_value={"items": []})
    )
    apps = SimpleNamespace(
        read_namespaced_deployment=Mock(return_value=workload)
    )
    networking = SimpleNamespace(
        list_namespaced_ingress=Mock(return_value={"items": []}),
        list_namespaced_network_policy=Mock(return_value={"items": []}),
    )
    rbac = SimpleNamespace(
        list_namespaced_role_binding=Mock(return_value={"items": []}),
        list_cluster_role_binding=Mock(return_value={"items": []}),
    )
    monkeypatch.setattr(
        cli,
        "load_current_context",
        lambda: (
            "test-cluster",
            {"core": core, "apps": apps, "networking": networking, "rbac": rbac},
        ),
    )
    trivy_output = (
        Path(__file__).parent / "fixtures" / "trivy-clean.json"
    ).read_text(encoding="utf-8")
    trivy_run = Mock(
        return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout=trivy_output, stderr=""
        )
    )
    monkeypatch.setattr("src.collectors.trivy.subprocess.run", trivy_run)

    code = cli.main(
        [
            "scan",
            "--namespace",
            "demo",
            "--kind",
            "Deployment",
            "--name",
            "vulnerable-api",
            "--allowed-namespace",
            "demo",
            "--output-dir",
            str(tmp_path),
        ]
    )

    assert code == cli.EXIT_OK
    apps.read_namespaced_deployment.assert_called_once_with(
        name="vulnerable-api", namespace="demo"
    )
    trivy_run.assert_called_once()
    trivy_command = trivy_run.call_args.args[0]
    assert trivy_command[:2] == ["trivy", "image"]
    assert trivy_command[-1] == "example.invalid/api:1"
    assert (tmp_path / "scan-report.json").exists()
    assert (tmp_path / "scan-report.md").exists()


@pytest.mark.parametrize(
    ("fail_on", "expected"),
    [("critical", cli.EXIT_OK), ("high", cli.EXIT_THRESHOLD), ("low", cli.EXIT_THRESHOLD), ("none", cli.EXIT_OK)],
)
def test_fail_on_uses_confirmed_severity_thresholds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fail_on: str,
    expected: int,
) -> None:
    code, _pipeline = _run_with_mocks(
        monkeypatch, tmp_path, _report(severity="high"), fail_on=fail_on
    )
    assert code == expected


def test_partial_scan_writes_reports_and_returns_distinct_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, _pipeline = _run_with_mocks(
        monkeypatch, tmp_path, _report(status="PARTIAL"), fail_on="high"
    )

    assert code == cli.EXIT_PARTIAL
    assert (tmp_path / "scan-report.json").exists()
    assert "PARTIAL" in (tmp_path / "scan-report.md").read_text(encoding="utf-8")


def test_invalid_report_is_rejected_before_either_file_is_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    invalid_report = _report()
    del invalid_report["summary"]

    code, _pipeline = _run_with_mocks(monkeypatch, tmp_path, invalid_report)

    assert code == cli.EXIT_ERROR
    assert not (tmp_path / "scan-report.json").exists()
    assert not (tmp_path / "scan-report.md").exists()


def test_missing_required_target_arguments_are_refused() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["scan", "--namespace", "demo"])
    assert exc_info.value.code == 2


def test_current_context_builds_allowlisted_read_only_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SimpleNamespace(
        list_kube_config_contexts=Mock(
            return_value=(
                [],
                {"name": "demo-context", "context": {"cluster": "demo-cluster"}},
            )
        ),
        load_kube_config=Mock(),
    )
    raw_core = SimpleNamespace(
        read_namespaced_pod=Mock(),
        list_namespaced_service=Mock(),
        delete_namespaced_pod=Mock(),
    )
    client = SimpleNamespace(
        CoreV1Api=Mock(return_value=raw_core),
        AppsV1Api=Mock(return_value=SimpleNamespace()),
        NetworkingV1Api=Mock(return_value=SimpleNamespace()),
        RbacAuthorizationV1Api=Mock(return_value=SimpleNamespace()),
    )
    monkeypatch.setattr(cli, "_kubernetes_modules", lambda: (client, config))

    cluster, clients = cli.load_current_context()

    assert cluster == "demo-cluster"
    config.load_kube_config.assert_called_once_with(context="demo-context")
    clients["core"].read_namespaced_pod(namespace="demo", name="api")
    raw_core.read_namespaced_pod.assert_called_once()
    with pytest.raises(AttributeError, match="not permitted"):
        clients["core"].delete_namespaced_pod
