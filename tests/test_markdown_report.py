"""Tests for safe, readable Markdown scan reports."""

from copy import deepcopy

from src.reporting.markdown import REDACTED, redact_report, render_markdown


def _report() -> dict:
    target = {
        "cluster": "test-cluster",
        "namespace": "demo",
        "kind": "Deployment",
        "name": "vulnerable-api",
        "container": None,
    }
    return {
        "scan_status": "COMPLETE",
        "target": target,
        "collector_status": {
            "workload": "COMPLETE",
            "security_context": "COMPLETE",
            "exposure": "COMPLETE",
            "network_policy": "COMPLETE",
            "rbac": "COMPLETE",
            "trivy": "COMPLETE",
        },
        "analyzer_status": {
            "security_context": "COMPLETE",
            "exposure": "COMPLETE",
            "network_policy": "COMPLETE",
            "rbac": "COMPLETE",
            "trivy": "COMPLETE",
        },
        "findings": [
            {
                "finding_id": "KSA-0123456789ab",
                "title": "Container allows privilege escalation",
                "status": "CONFIRMED",
                "severity": "high",
                "score": 70,
                "confidence": "high",
                "target": {**target, "container": "api"},
                "evidence": [
                    {
                        "source": "kubernetes.security_context",
                        "observed_at": "2026-01-02T03:04:05Z",
                        "collector_version": "1.0.0",
                        "details": {
                            "allowPrivilegeEscalation": True,
                            "annotations": {
                                "example.invalid/api-key": "do-not-display"
                            },
                            "environment": {
                                "name": "DATABASE_PASSWORD",
                                "value": "also-do-not-display",
                            },
                        },
                    }
                ],
                "risk_factors": ["allow_privilege_escalation"],
                "attack_path": None,
                "blast_radius": None,
                "recommendations": [
                    "Set securityContext.allowPrivilegeEscalation to false."
                ],
                "limitations": [
                    "This finding identifies configuration risk, not exploitation."
                ],
            }
        ],
        "attack_paths": [],
        "ai_status": "DISABLED",
        "ai_analysis": None,
        "evidence_gaps": [],
        "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    }


def test_markdown_contains_required_sections_and_traceable_evidence() -> None:
    markdown = render_markdown(_report())

    for heading in (
        "## Target and Scan Status",
        "## Severity Summary",
        "## Confirmed Findings",
        "## Plausible Attack Paths",
        "## AI Interpretation",
        "#### Evidence",
        "## Recommendations",
        "## Evidence Gaps",
        "## Collection or Analysis Failures",
    ):
        assert heading in markdown
    assert "KSA-0123456789ab" in markdown
    assert "kubernetes.security_context" in markdown
    assert "No exploitation was confirmed" in markdown
    assert "vulnerable-api" in markdown
    assert "AI analysis was not requested" in markdown


def test_plausible_paths_and_ai_interpretation_are_separate_from_evidence() -> None:
    report = _report()
    finding_id = report["findings"][0]["finding_id"]
    path_id = "KAP-0123456789ab"
    report["attack_paths"] = [
        {
            "attack_path_id": path_id,
            "status": "PLAUSIBLE",
            "title": "Exposure may combine with workload weakness",
            "score": 55,
            "severity": "high",
            "supporting_finding_ids": [finding_id],
            "risk_factors": ["public_exposure", "high_cve"],
            "explanation": "The confirmed signals form a plausible sequence.",
            "limitations": ["This does not establish exploitation."],
        }
    ]
    report["ai_status"] = "SUCCESS"
    report["ai_analysis"] = {
        "executive_summary": "Prioritize review of the plausible sequence.",
        "attack_path_explanations": [
            {
                "attack_path_id": path_id,
                "explanation": "The path links the supplied deterministic signals.",
            }
        ],
        "priority_order": [
            {
                "position": 1,
                "reference_type": "attack_path",
                "reference_id": path_id,
                "rationale": "It combines multiple conditions.",
            }
        ],
        "remediation_steps": [
            {
                "finding_ids": [finding_id],
                "attack_path_ids": [path_id],
                "step": "Restrict exposure and remediate the workload weakness.",
            }
        ],
        "operator_review_notes": [
            {
                "finding_ids": [finding_id],
                "attack_path_ids": [],
                "note": "Confirm whether exposure is intended.",
            }
        ],
        "limitations": ["AI output is interpretive and not evidence."],
    }

    markdown = render_markdown(report)

    confirmed_index = markdown.index("## Confirmed Findings")
    plausible_index = markdown.index("## Plausible Attack Paths")
    ai_index = markdown.index("## AI Interpretation")
    assert confirmed_index < plausible_index < ai_index
    assert "deterministic hypotheses, not collected evidence" in markdown
    assert "AI-generated text is interpretation only" in markdown
    assert path_id in markdown
    assert "Prioritize review" in markdown


def test_markdown_and_redacted_json_never_include_credential_values() -> None:
    report = _report()
    original = deepcopy(report)

    safe = redact_report(report)
    markdown = render_markdown(report)

    assert report == original
    assert "do-not-display" not in str(safe)
    assert "also-do-not-display" not in str(safe)
    assert "do-not-display" not in markdown
    assert "also-do-not-display" not in markdown
    assert REDACTED in markdown


def test_partial_report_lists_gaps_and_failures_without_raw_error_text() -> None:
    report = _report()
    report["scan_status"] = "PARTIAL"
    report["collector_status"]["trivy"] = "COLLECTION_FAILED"
    report["evidence_gaps"] = [
        {
            "component": "trivy",
            "stage": "COLLECTION",
            "status": "COLLECTION_FAILED",
            "errors": ["registry token=super-secret"],
        }
    ]

    markdown = render_markdown(report)

    assert "COLLECTION_FAILED" in markdown
    assert "trivy" in markdown
    assert "super-secret" not in markdown
    assert "Failure details withheld" in markdown
