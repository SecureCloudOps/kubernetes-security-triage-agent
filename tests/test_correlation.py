"""Tests for deterministic, evidence-constrained attack-path correlation."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from jsonschema import validate

from src.analysis.correlation import CorrelationEngine, correlate_findings
from src.models.attack_path import AttackPath


ROOT = Path(__file__).parents[1]
SCHEMA = ROOT / "schemas" / "attack-path.schema.json"
CONFIG = ROOT / "config" / "risk-rules.yaml"
TARGET = {
    "cluster": "kind-security",
    "namespace": "demo",
    "kind": "Deployment",
    "name": "payments",
    "container": None,
}


def _finding(
    suffix: int,
    factor: str,
    *,
    status: str = "CONFIRMED",
    target: dict | None = None,
) -> dict:
    return {
        "finding_id": f"KSA-{suffix:012x}",
        "status": status,
        "target": deepcopy(target or TARGET),
        "risk_factors": [factor],
    }


def _validate(paths: list[dict]) -> None:
    with SCHEMA.open(encoding="utf-8") as source:
        schema = json.load(source)
    for path in paths:
        validate(instance=path, schema=schema)


@pytest.mark.parametrize(
    ("left", "right", "title_fragment"),
    [
        ("public_exposure", "critical_cve", "image vulnerability"),
        ("public_exposure", "high_cve", "image vulnerability"),
        ("public_exposure", "privileged_container", "privileged or root"),
        ("public_exposure", "runs_as_root", "privileged or root"),
        ("privileged_container", "cluster_admin_binding", "excessive RBAC"),
        ("secrets_read_permission", "pod_exec_permission", "pod execution"),
        ("public_exposure", "missing_network_policy", "network isolation"),
    ],
)
def test_supported_confirmed_pairs_create_plausible_paths(
    left: str, right: str, title_fragment: str
) -> None:
    paths = correlate_findings([_finding(1, left), _finding(2, right)])

    assert len(paths) == 1
    path = paths[0]
    assert path["status"] == "PLAUSIBLE"
    assert path["severity"] == "high"
    assert path["risk_factors"] == sorted([left, right])
    assert path["supporting_finding_ids"] == [
        "KSA-000000000001",
        "KSA-000000000002",
    ]
    assert title_fragment in path["title"]
    assert "exploitation" in " ".join(path["limitations"]).lower()
    assert "exploitation occurred" not in path["explanation"].lower()
    _validate(paths)


def test_unconfirmed_and_isolated_findings_never_create_paths() -> None:
    findings = [
        _finding(1, "public_exposure"),
        _finding(2, "critical_cve", status="INSUFFICIENT_EVIDENCE"),
        _finding(3, "secrets_read_permission"),
    ]

    assert correlate_findings(findings) == []


def test_potential_external_exposure_remains_explicitly_unconfirmed_in_path() -> None:
    path = correlate_findings(
        [
            _finding(1, "potential_external_exposure"),
            _finding(2, "critical_cve"),
        ]
    )[0]

    assert "potential_external_exposure" in path["risk_factors"]
    assert "public_exposure" not in path["risk_factors"]
    narrative = " ".join([path["explanation"], *path["limitations"]]).lower()
    assert "public reachability was not confirmed" in narrative


def test_findings_from_different_workloads_are_not_related() -> None:
    other = {**TARGET, "name": "unrelated-api"}

    assert correlate_findings(
        [
            _finding(1, "public_exposure"),
            _finding(2, "critical_cve", target=other),
        ]
    ) == []


def test_repeated_factor_is_scored_once_but_all_findings_are_supported() -> None:
    paths = correlate_findings(
        [
            _finding(3, "critical_cve"),
            _finding(1, "public_exposure"),
            _finding(2, "critical_cve"),
        ]
    )

    assert len(paths) == 1
    assert paths[0]["score"] == 55
    assert paths[0]["risk_factors"] == ["critical_cve", "public_exposure"]
    assert paths[0]["supporting_finding_ids"] == [
        "KSA-000000000001",
        "KSA-000000000002",
        "KSA-000000000003",
    ]


def test_score_is_capped_at_100_and_each_matched_weight_is_added_once(
    tmp_path: Path,
) -> None:
    with CONFIG.open(encoding="utf-8") as source:
        config = yaml.safe_load(source)
    config["weights"]["privileged_container"] = 80
    config["weights"]["cluster_admin_binding"] = 80
    custom = tmp_path / "risk-rules.yaml"
    custom.write_text(yaml.safe_dump(config), encoding="utf-8")

    paths = CorrelationEngine(config_path=custom).correlate(
        [
            _finding(1, "privileged_container"),
            _finding(2, "privileged_container"),
            _finding(3, "cluster_admin_binding"),
        ]
    )

    assert paths[0]["score"] == 100
    assert paths[0]["risk_factors"] == [
        "cluster_admin_binding",
        "privileged_container",
    ]


def test_output_ids_and_order_are_stable_for_reordered_input() -> None:
    findings = [
        _finding(4, "missing_network_policy"),
        _finding(3, "runs_as_root"),
        _finding(2, "critical_cve"),
        _finding(1, "public_exposure"),
    ]

    first = correlate_findings(deepcopy(findings))
    second = correlate_findings(list(reversed(deepcopy(findings))))

    assert first == second
    assert len(first) == 3
    assert all(path["attack_path_id"].startswith("KAP-") for path in first)
    assert all(len(path["attack_path_id"]) == 16 for path in first)


def test_partial_report_adds_generic_and_specific_evidence_gap_limitations() -> None:
    report = {
        "scan_status": "PARTIAL",
        "findings": [
            _finding(1, "public_exposure"),
            _finding(2, "critical_cve"),
        ],
        "evidence_gaps": [
            {
                "component": "rbac",
                "stage": "COLLECTION",
                "status": "COLLECTION_FAILED",
                "errors": ["forbidden"],
            }
        ],
    }

    path = correlate_findings(report)[0]
    limitations = " ".join(path["limitations"]).lower()

    assert "scan was partial" in limitations
    assert "evidence gap" in limitations
    assert "rbac" in limitations
    assert path["status"] == "PLAUSIBLE"


def test_malformed_and_ambiguous_evidence_fails_closed() -> None:
    malformed = _finding(1, "public_exposure")
    malformed["target"] = {"namespace": "demo"}
    ambiguous = _finding(2, "critical_cve")
    ambiguous["finding_id"] = "not-a-finding-id"

    assert correlate_findings([malformed, ambiguous]) == []


def test_attack_path_model_round_trips_exact_schema_shape() -> None:
    value = correlate_findings(
        [_finding(1, "secrets_read_permission"), _finding(2, "pod_exec_permission")]
    )[0]

    assert AttackPath.from_dict(value).to_dict() == value
    assert set(value) == {
        "attack_path_id",
        "status",
        "title",
        "score",
        "severity",
        "supporting_finding_ids",
        "risk_factors",
        "explanation",
        "limitations",
    }
