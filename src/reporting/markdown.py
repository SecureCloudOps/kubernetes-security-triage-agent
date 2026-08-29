"""Safe, deterministic Markdown rendering for scan reports."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from src.collectors.trivy import EVIDENCE_SOURCE as TRIVY_EVIDENCE_SOURCE

REDACTED = "[REDACTED]"
_AGGREGATED_VULNERABILITY_SEVERITIES = frozenset({"medium", "low", "info"})

_SENSITIVE_KEY_PARTS = (
    "apikey",
    "authorization",
    "clientcertificatedata",
    "clientkey",
    "credential",
    "kubeconfig",
    "password",
    "passwd",
    "privatekey",
    "secret",
    "token",
)
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[-_ ]?key|authorization|credential)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_URL_CREDENTIAL_RE = re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?-----END [^-\n]*PRIVATE KEY-----",
    re.DOTALL,
)


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _is_sensitive_key(value: Any) -> bool:
    key = _normalized_key(value)
    return any(part in key for part in _SENSITIVE_KEY_PARTS)


def _redact_string(value: str) -> str:
    value = _PRIVATE_KEY_RE.sub(REDACTED, value)
    value = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", value)
    return _ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", value)


def _redact(value: Any, *, key: str | None = None) -> Any:
    if key is not None and _is_sensitive_key(key):
        return REDACTED
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        named_secret = _is_sensitive_key(value.get("name", ""))
        kubernetes_secret = str(value.get("kind", "")).lower() == "secret"
        for child_key, child_value in value.items():
            child_key_text = str(child_key)
            if (named_secret and child_key_text.lower() == "value") or (
                kubernetes_secret and child_key_text in {"data", "stringData", "string_data"}
            ):
                result[child_key_text] = REDACTED
            elif child_key_text == "errors" and isinstance(child_value, list):
                # API and process exceptions can include headers, command output, or
                # registry details. The component/status remain available elsewhere.
                result[child_key_text] = [
                    "Failure details withheld to prevent sensitive data disclosure."
                    for _ in child_value
                ]
            else:
                result[child_key_text] = _redact(child_value, key=child_key_text)
        return result
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return deepcopy(value)


def redact_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy with credential-like fields and failure details redacted."""

    if not isinstance(report, Mapping):
        raise TypeError("report must be a mapping")
    redacted = _redact(report)
    if not isinstance(redacted, dict):  # pragma: no cover - guarded above
        raise TypeError("report must be a mapping")
    return redacted


def _cell(value: Any) -> str:
    if value is None or value == "":
        return "—"
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _target_text(target: Mapping[str, Any]) -> str:
    base = f"{target.get('kind', 'unknown')} {target.get('namespace', 'unknown')}/{target.get('name', 'unknown')}"
    container = target.get("container")
    return f"{base} (container: {container})" if container else base


def _json_block(value: Any) -> str:
    rendered = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    # Do not allow evidence text to terminate its own Markdown fence.
    return rendered.replace("```", "` ` `")


def _is_trivy_vulnerability_finding(finding: Mapping[str, Any]) -> bool:
    evidence_items = finding.get("evidence", [])
    if not isinstance(evidence_items, list):
        return False
    return any(
        isinstance(evidence, Mapping)
        and evidence.get("source") == TRIVY_EVIDENCE_SOURCE
        and isinstance(evidence.get("details"), Mapping)
        and isinstance(evidence["details"].get("vulnerability_id"), str)
        for evidence in evidence_items
    )


def _is_aggregated_vulnerability_finding(finding: Mapping[str, Any]) -> bool:
    return (
        _is_trivy_vulnerability_finding(finding)
        and finding.get("severity") in _AGGREGATED_VULNERABILITY_SEVERITIES
    )


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render a scan report as readable Markdown without exposing secrets."""

    safe = redact_report(report)
    target = safe.get("target")
    summary = safe.get("summary")
    findings = safe.get("findings")
    attack_paths = safe.get("attack_paths")
    ai_status = safe.get("ai_status")
    ai_analysis = safe.get("ai_analysis")
    ai_error = safe.get("ai_error")
    gaps = safe.get("evidence_gaps")
    if not isinstance(target, Mapping):
        raise ValueError("report.target must be an object")
    if not isinstance(summary, Mapping):
        raise ValueError("report.summary must be an object")
    if not isinstance(findings, list):
        raise ValueError("report.findings must be a list")
    if not isinstance(attack_paths, list):
        raise ValueError("report.attack_paths must be a list")
    if ai_status not in {"DISABLED", "SKIPPED", "SUCCESS", "FAILED"}:
        raise ValueError("report.ai_status is invalid")
    if ai_status == "SUCCESS" and not isinstance(ai_analysis, Mapping):
        raise ValueError("successful AI analysis must be an object")
    if ai_status != "SUCCESS" and ai_analysis is not None:
        raise ValueError("non-successful AI analysis must be null")
    if ai_status == "FAILED" and not isinstance(ai_error, Mapping):
        raise ValueError("failed AI analysis must include an error")
    if ai_status != "FAILED" and ai_error is not None:
        raise ValueError("non-failed AI analysis must not include an error")
    if not isinstance(gaps, list):
        raise ValueError("report.evidence_gaps must be a list")

    lines = [
        "# Kubernetes Security Scan Report",
        "",
        "**No exploitation was confirmed by this scan.** Findings describe observed configuration or vulnerability risk only.",
        "",
        "## Target and Scan Status",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Cluster | {_cell(target.get('cluster'))} |",
        f"| Namespace | {_cell(target.get('namespace'))} |",
        f"| Kind | {_cell(target.get('kind'))} |",
        f"| Workload | {_cell(target.get('name'))} |",
        f"| Container | {_cell(target.get('container'))} |",
        f"| Scan status | **{_cell(safe.get('scan_status'))}** |",
        "",
        "## Severity Summary",
        "",
        "| Critical | High | Medium | Low | Info |",
        "| ---: | ---: | ---: | ---: | ---: |",
        "| " + " | ".join(str(summary.get(level, 0)) for level in ("critical", "high", "medium", "low", "info")) + " |",
        "",
        "## Confirmed Findings",
        "",
    ]

    confirmed = [
        finding
        for finding in findings
        if isinstance(finding, Mapping) and finding.get("status") == "CONFIRMED"
    ]
    if not confirmed:
        lines.extend(["No confirmed findings.", ""])
    detailed_confirmed = [
        finding
        for finding in confirmed
        if not _is_aggregated_vulnerability_finding(finding)
    ]
    for finding in detailed_confirmed:
        finding_target = finding.get("target", {})
        if not isinstance(finding_target, Mapping):
            finding_target = {}
        lines.extend(
            [
                f"### {_cell(finding.get('finding_id'))}: {_cell(finding.get('title'))}",
                "",
                "| Severity | Score | Confidence | Target |",
                "| --- | ---: | --- | --- |",
                f"| {_cell(finding.get('severity'))} | {_cell(finding.get('score'))} | {_cell(finding.get('confidence'))} | {_cell(_target_text(finding_target))} |",
                "",
                "#### Evidence",
                "",
            ]
        )
        evidence_items = finding.get("evidence", [])
        if not isinstance(evidence_items, list) or not evidence_items:
            lines.extend(["No evidence was attached.", ""])
        else:
            for index, evidence in enumerate(evidence_items, start=1):
                if not isinstance(evidence, Mapping):
                    continue
                lines.extend(
                    [
                        f"**Evidence {index}:** `{_cell(evidence.get('source'))}`; observed {_cell(evidence.get('observed_at'))}; collector {_cell(evidence.get('collector_version'))}",
                        "",
                        "```json",
                        _json_block(evidence.get("details", {})),
                        "```",
                        "",
                    ]
                )

    aggregated_vulnerability_counts = {
        severity: sum(
            1
            for finding in confirmed
            if _is_trivy_vulnerability_finding(finding)
            and finding.get("severity") == severity
        )
        for severity in ("medium", "low", "info")
    }
    if any(aggregated_vulnerability_counts.values()):
        lines.extend(
            [
                "### Aggregated Medium, Low, and Info Vulnerabilities",
                "",
                "Individual details for these vulnerability severities are omitted "
                "from Markdown. Complete results remain available in the JSON report.",
                "",
                "| Severity | Vulnerability count |",
                "| --- | ---: |",
                f"| Medium | {aggregated_vulnerability_counts['medium']} |",
                f"| Low | {aggregated_vulnerability_counts['low']} |",
                f"| Info | {aggregated_vulnerability_counts['info']} |",
                "",
            ]
        )

    lines.extend(
        [
            "## Plausible Attack Paths",
            "",
            "**These are deterministic hypotheses, not collected evidence or proof of exploitation.**",
            "",
        ]
    )
    plausible = [
        path
        for path in attack_paths
        if isinstance(path, Mapping) and path.get("status") == "PLAUSIBLE"
    ]
    if not plausible:
        lines.extend(["No plausible attack paths were generated.", ""])
    for path in plausible:
        supporting = path.get("supporting_finding_ids", [])
        supporting_text = (
            ", ".join(str(item) for item in supporting)
            if isinstance(supporting, list)
            else str(supporting)
        )
        lines.extend(
            [
                f"### {_cell(path.get('attack_path_id'))}: {_cell(path.get('title'))}",
                "",
                "| Status | Severity | Score | Supporting confirmed findings |",
                "| --- | --- | ---: | --- |",
                f"| PLAUSIBLE | {_cell(path.get('severity'))} | {_cell(path.get('score'))} | {_cell(supporting_text)} |",
                "",
                f"**Hypothesis:** {_cell(path.get('explanation'))}",
                "",
            ]
        )
        limitations = path.get("limitations", [])
        if isinstance(limitations, list) and limitations:
            lines.extend(["**Limitations:**", ""])
            lines.extend(f"- {_cell(item)}" for item in limitations)
            lines.append("")

    lines.extend(
        [
            "## AI Interpretation",
            "",
            f"**AI status:** {_cell(ai_status)}",
            "",
            "**AI-generated text is interpretation only. It is not collected evidence and cannot confirm exploitation.**",
            "",
        ]
    )
    if ai_status == "DISABLED":
        lines.extend(["AI analysis was not requested.", ""])
    elif ai_status == "SKIPPED":
        lines.extend(
            ["AI analysis was requested but skipped because there was nothing eligible to interpret.", ""]
        )
    elif ai_status == "FAILED":
        code = ai_error.get("code") if isinstance(ai_error, Mapping) else "unknown"
        lines.extend(
            [
                f"AI analysis failed: {_cell(code)}.",
                "Deterministic findings and plausible paths remain unchanged.",
                "",
            ]
        )
    elif isinstance(ai_analysis, Mapping):
        lines.extend(
            [
                "### Executive Summary",
                "",
                f"> {_cell(ai_analysis.get('executive_summary'))}",
                "",
            ]
        )

        explanations = ai_analysis.get("attack_path_explanations", [])
        lines.extend(["### Attack Path Explanations", ""])
        if isinstance(explanations, list) and explanations:
            lines.extend(
                [
                    "| Plausible path | AI explanation |",
                    "| --- | --- |",
                ]
            )
            for item in explanations:
                if isinstance(item, Mapping):
                    lines.append(
                        f"| {_cell(item.get('attack_path_id'))} | {_cell(item.get('explanation'))} |"
                    )
            lines.append("")
        else:
            lines.extend(["No AI attack-path explanations were generated.", ""])

        priorities = ai_analysis.get("priority_order", [])
        lines.extend(["### AI Priority Order", ""])
        if isinstance(priorities, list) and priorities:
            lines.extend(
                [
                    "| Position | Type | Reference | Rationale |",
                    "| ---: | --- | --- | --- |",
                ]
            )
            for item in priorities:
                if isinstance(item, Mapping):
                    lines.append(
                        f"| {_cell(item.get('position'))} | {_cell(item.get('reference_type'))} | {_cell(item.get('reference_id'))} | {_cell(item.get('rationale'))} |"
                    )
            lines.append("")
        else:
            lines.extend(["No AI priority order was generated.", ""])

        remediation_steps = ai_analysis.get("remediation_steps", [])
        lines.extend(["### AI Remediation Interpretation", ""])
        if isinstance(remediation_steps, list) and remediation_steps:
            for item in remediation_steps:
                if not isinstance(item, Mapping):
                    continue
                references = list(item.get("finding_ids", [])) + list(
                    item.get("attack_path_ids", [])
                )
                lines.append(
                    f"- **{_cell(', '.join(str(value) for value in references))}:** {_cell(item.get('step'))}"
                )
            lines.append("")
        else:
            lines.extend(["No AI remediation interpretation was generated.", ""])

        review_notes = ai_analysis.get("operator_review_notes", [])
        lines.extend(["### Operator Review Notes", ""])
        if isinstance(review_notes, list) and review_notes:
            for item in review_notes:
                if not isinstance(item, Mapping):
                    continue
                references = list(item.get("finding_ids", [])) + list(
                    item.get("attack_path_ids", [])
                )
                lines.append(
                    f"- **{_cell(', '.join(str(value) for value in references))}:** {_cell(item.get('note'))}"
                )
            lines.append("")
        else:
            lines.extend(["No operator review notes were generated.", ""])

        ai_limitations = ai_analysis.get("limitations", [])
        lines.extend(["### AI Limitations", ""])
        if isinstance(ai_limitations, list) and ai_limitations:
            lines.extend(f"- {_cell(item)}" for item in ai_limitations)
            lines.append("")
        else:
            lines.extend(["No additional AI limitations were generated.", ""])

    lines.extend(["## Recommendations", ""])
    recommendation_rows: list[tuple[str, str]] = []
    seen_recommendations: set[tuple[str, str]] = set()
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        if _is_aggregated_vulnerability_finding(finding):
            continue
        finding_id = str(finding.get("finding_id", "unknown"))
        recommendations = finding.get("recommendations", [])
        if not isinstance(recommendations, list):
            continue
        for recommendation in recommendations:
            row = (finding_id, str(recommendation))
            if row not in seen_recommendations:
                seen_recommendations.add(row)
                recommendation_rows.append(row)
    if recommendation_rows:
        lines.extend(["| Finding | Recommendation |", "| --- | --- |"])
        lines.extend(
            f"| {_cell(finding_id)} | {_cell(recommendation)} |"
            for finding_id, recommendation in recommendation_rows
        )
        lines.append("")
    else:
        lines.extend(["No recommendations were generated.", ""])

    lines.extend(["## Evidence Gaps", ""])
    gap_rows: list[tuple[str, str, str, str]] = []
    for gap in gaps:
        if not isinstance(gap, Mapping):
            continue
        errors = gap.get("errors", [])
        error_text = "; ".join(str(item) for item in errors) if isinstance(errors, list) else str(errors)
        gap_rows.append(
            (
                str(gap.get("component", "unknown")),
                str(gap.get("stage", "unknown")),
                str(gap.get("status", "unknown")),
                error_text,
            )
        )
    for finding in findings:
        if isinstance(finding, Mapping) and finding.get("status") != "CONFIRMED":
            limitations = finding.get("limitations", [])
            detail = "; ".join(str(item) for item in limitations) if isinstance(limitations, list) else str(limitations)
            gap_rows.append(
                (
                    str(finding.get("finding_id", "unknown")),
                    "FINDING",
                    str(finding.get("status", "unknown")),
                    detail or str(finding.get("title", "Evidence was insufficient")),
                )
            )
    if gap_rows:
        lines.extend(
            [
                "| Component | Stage | Status | Detail |",
                "| --- | --- | --- | --- |",
            ]
        )
        lines.extend(
            f"| {_cell(component)} | {_cell(stage)} | {_cell(status)} | {_cell(detail)} |"
            for component, stage, status, detail in gap_rows
        )
        lines.append("")
    else:
        lines.extend(["No evidence gaps were reported.", ""])

    lines.extend(["## Collection or Analysis Failures", ""])
    failures = [row for row in gap_rows if row[2] in {"COLLECTION_FAILED", "ANALYSIS_FAILED"}]
    if failures:
        lines.extend(
            [
                "| Component | Stage | Status | Detail |",
                "| --- | --- | --- | --- |",
            ]
        )
        lines.extend(
            f"| {_cell(component)} | {_cell(stage)} | {_cell(status)} | {_cell(detail)} |"
            for component, stage, status, detail in failures
        )
        lines.append("")
    else:
        lines.extend(["No collection or analysis failures were reported.", ""])

    return "\n".join(lines)


__all__ = ["REDACTED", "redact_report", "render_markdown"]
