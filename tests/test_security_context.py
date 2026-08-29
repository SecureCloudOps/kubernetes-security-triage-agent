"""Offline tests for normalized Kubernetes security-context evidence."""

from datetime import datetime, timezone
from pathlib import Path

import yaml

from src.collectors.security_context import collect_security_context
from src.models import Evidence

FIXTURES = Path(__file__).parent / "fixtures"
OBSERVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _load_fixture(name: str) -> dict:
    with (FIXTURES / name).open(encoding="utf-8") as fixture:
        return yaml.safe_load(fixture)


def test_secure_deployment_produces_hardened_container_evidence() -> None:
    evidence = collect_security_context(
        _load_fixture("secure-deployment.yaml"),
        cluster="fixture-cluster",
        observed_at=OBSERVED_AT,
    )

    assert len(evidence) == 1
    item = evidence[0]
    assert isinstance(item, Evidence)
    assert item.source == "kubernetes.security_context"
    assert item.observed_at == OBSERVED_AT
    assert item.details == {
        "workload": {
            "cluster": "fixture-cluster",
            "namespace": "production",
            "kind": "Deployment",
            "name": "secure-api",
        },
        "container": {"name": "api", "type": "container"},
        "privileged": False,
        "runAsNonRoot": True,
        "runAsUser": 10001,
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"add": [], "drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
        "hostNetwork": False,
        "hostPID": False,
        "hostIPC": False,
    }


def test_insecure_deployment_produces_privileged_root_evidence() -> None:
    evidence = collect_security_context(
        _load_fixture("insecure-deployment.yaml"),
        cluster="fixture-cluster",
        observed_at=OBSERVED_AT,
    )

    assert len(evidence) == 1
    details = evidence[0].details
    assert details["privileged"] is True
    assert details["runAsNonRoot"] is False
    assert details["runAsUser"] == 0
    assert details["allowPrivilegeEscalation"] is True
    assert details["readOnlyRootFilesystem"] is False
    assert details["capabilities"] == {
        "add": ["SYS_ADMIN", "NET_ADMIN"],
        "drop": [],
    }
    assert details["seccompProfile"] == {"type": "Unconfined"}
    assert details["hostNetwork"] is True
    assert details["hostPID"] is True
    assert details["hostIPC"] is True


def test_missing_values_remain_unknown_instead_of_becoming_false() -> None:
    manifest = _load_fixture("secure-deployment.yaml")
    pod_spec = manifest["spec"]["template"]["spec"]
    pod_spec.pop("hostNetwork")
    pod_spec.pop("hostPID")
    pod_spec.pop("hostIPC")
    pod_spec.pop("securityContext")
    pod_spec["containers"][0].pop("securityContext")

    details = collect_security_context(
        manifest,
        observed_at=OBSERVED_AT,
    )[0].details

    assert details["privileged"] is None
    assert details["runAsNonRoot"] is None
    assert details["runAsUser"] is None
    assert details["allowPrivilegeEscalation"] is None
    assert details["readOnlyRootFilesystem"] is None
    assert details["capabilities"] == {"add": None, "drop": None}
    assert details["seccompProfile"] is None
    assert details["hostNetwork"] is None
    assert details["hostPID"] is None
    assert details["hostIPC"] is None


def test_returns_one_evidence_object_per_container() -> None:
    manifest = _load_fixture("secure-deployment.yaml")
    manifest["spec"]["template"]["spec"]["containers"].append(
        {"name": "metrics", "image": "example.invalid/metrics:1.0.0"}
    )

    evidence = collect_security_context(manifest, observed_at=OBSERVED_AT)

    assert [item.details["container"]["name"] for item in evidence] == [
        "api",
        "metrics",
    ]
    assert evidence[1].details["privileged"] is None
    assert evidence[1].details["runAsNonRoot"] is True


def test_none_container_values_inherit_pod_security_context() -> None:
    manifest = _load_fixture("secure-deployment.yaml")
    container_context = manifest["spec"]["template"]["spec"]["containers"][0][
        "securityContext"
    ]
    container_context["runAsUser"] = None
    container_context["runAsNonRoot"] = None
    container_context["seccompProfile"] = None

    details = collect_security_context(manifest, observed_at=OBSERVED_AT)[0].details

    assert details["runAsUser"] == 10001
    assert details["runAsNonRoot"] is True
    assert details["seccompProfile"] == {"type": "RuntimeDefault"}
