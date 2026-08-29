"""Integration coverage for the normalized workload-to-security-context contract."""

from datetime import datetime, timezone
from pathlib import Path

import yaml

from src.analysis.security_context_rules import analyze_security_context
from src.collectors.kubernetes_workload import KubernetesWorkloadCollector
from src.collectors.security_context import SecurityContextCollector

DEMO_MANIFEST = (
    Path(__file__).parents[1] / "demo" / "manifests" / "vulnerable-workload.yaml"
)
OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

_KUBERNETES_MODEL_KEYS = {
    "allowPrivilegeEscalation": "allow_privilege_escalation",
    "automountServiceAccountToken": "automount_service_account_token",
    "readOnlyRootFilesystem": "read_only_root_filesystem",
    "runAsGroup": "run_as_group",
    "runAsNonRoot": "run_as_non_root",
    "runAsUser": "run_as_user",
    "securityContext": "security_context",
    "serviceAccountName": "service_account_name",
}


def _vulnerable_deployment() -> dict:
    with DEMO_MANIFEST.open(encoding="utf-8") as source:
        resources = list(yaml.safe_load_all(source))
    return next(resource for resource in resources if resource.get("kind") == "Deployment")


def _as_kubernetes_model_dict(value):
    if isinstance(value, dict):
        return {
            _KUBERNETES_MODEL_KEYS.get(key, key): _as_kubernetes_model_dict(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_as_kubernetes_model_dict(item) for item in value]
    return value


class _KubernetesModel:
    def to_dict(self) -> dict:
        workload = _as_kubernetes_model_dict(_vulnerable_deployment())
        container_context = workload["spec"]["template"]["spec"]["containers"][0][
            "security_context"
        ]
        container_context["run_as_user"] = None
        container_context["seccomp_profile"] = None
        return workload


class _DeploymentClient:
    def read_namespaced_deployment(self, *, name: str, namespace: str) -> dict:
        deployment = _vulnerable_deployment()
        assert (name, namespace) == (
            deployment["metadata"]["name"],
            deployment["metadata"]["namespace"],
        )
        return _KubernetesModel()


def test_vulnerable_workload_pod_spec_produces_required_security_findings() -> None:
    workload_result = KubernetesWorkloadCollector(
        _DeploymentClient(),
        approved_namespace="vulnerable-demo",
    ).collect(
        namespace="vulnerable-demo",
        kind="Deployment",
        name="vulnerable-web",
        cluster="ksta-demo",
        observed_at=OBSERVED_AT,
    )
    pod_spec = workload_result.evidence[0].details["pod_spec"]
    assert "security_context" in pod_spec
    assert "securityContext" not in pod_spec

    security_evidence = SecurityContextCollector().collect(
        pod_spec,
        target=workload_result.target,
        observed_at=OBSERVED_AT,
    )
    findings = analyze_security_context(security_evidence)
    risk_factors = {factor for finding in findings for factor in finding["risk_factors"]}

    assert {
        "privileged_container",
        "runs_as_root",
        "allow_privilege_escalation",
    } <= risk_factors
    assert "Container is configured to run as UID 0" in {
        finding["title"] for finding in findings
    }
