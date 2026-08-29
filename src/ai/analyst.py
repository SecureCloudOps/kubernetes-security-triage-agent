"""Strict adapter between deterministic findings and the OpenAI Responses API.

This module has no Kubernetes client, tool, subprocess, or manifest interface. It
allowlists a small evidence summary before a model call and validates every model
reference before returning the non-authoritative analysis.
"""

from __future__ import annotations

import json
import os
import re
import unicodedata
from collections.abc import Iterable, Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .prompts import SYSTEM_PROMPT, build_analysis_input


AI_ANALYSIS_COMPLETE = "COMPLETE"
AI_ANALYSIS_SKIPPED = "SKIPPED"
AI_ANALYSIS_FAILED = "AI_ANALYSIS_FAILED"
CONFIGURATION_FAILED = "CONFIGURATION_FAILED"
API_FAILED = "API_FAILED"
INCOMPLETE_RESPONSE = "INCOMPLETE_RESPONSE"
SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"
REFERENCE_VALIDATION_FAILED = "REFERENCE_VALIDATION_FAILED"
SAFETY_VALIDATION_FAILED = "SAFETY_VALIDATION_FAILED"
DEFAULT_MODEL = "gpt-5-mini"
DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "schemas" / "ai-analysis.schema.json"
)

MAX_FINDINGS = 100
MAX_ATTACK_PATHS = 100
MAX_EVIDENCE_GAPS = 50
MAX_LIST_ITEMS = 20
MAX_TEXT_CHARS = 800
MAX_MODEL_INPUT_CHARS = 100_000
MAX_MODEL_OUTPUT_CHARS = 200_000
MAX_OUTPUT_TOKENS = 4_000

_ERROR_DETAILS = {
    CONFIGURATION_FAILED: (
        "configuration",
        "AI analysis configuration failed.",
    ),
    API_FAILED: ("api", "AI API request failed."),
    INCOMPLETE_RESPONSE: ("response", "Model response was incomplete."),
    SCHEMA_VALIDATION_FAILED: (
        "schema",
        "Model response failed schema validation.",
    ),
    REFERENCE_VALIDATION_FAILED: (
        "reference",
        "Model response referenced unknown or invalid evidence.",
    ),
    SAFETY_VALIDATION_FAILED: (
        "safety",
        "Model response failed safety validation.",
    ),
}
_KNOWN_INCOMPLETE_REASONS = frozenset(
    {"max_output_tokens", "content_filter", "unknown"}
)

_FINDING_ID = re.compile(r"^KSA-[0-9a-fA-F]{12}$")
_ATTACK_PATH_ID = re.compile(r"^KAP-[0-9a-f]{12}$")
_ANY_EVIDENCE_ID = re.compile(
    r"\b(?:KSA-[0-9a-fA-F]{12}|KAP-[0-9a-f]{12})\b"
)
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

_SENSITIVE_PATTERNS = (
    re.compile(
        r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
        re.I,
    ),
    re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b"),
    re.compile(
        r"\b(?:password|passwd|token|secret|api[ _-]?key|client[ _-]?secret)"
        r"\s*[:=]\s*['\"]?[^\s,;'\"]{4,}",
        re.I,
    ),
)
_ASSERTIVE_INCIDENT_PATTERNS = (
    re.compile(
        r"\b(?:exploitation|compromise|breach|intrusion|attack)\s+"
        r"(?:has\s+)?(?:occurred|succeeded|was successful|is confirmed|was confirmed|was detected)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:was|were|is|are|has been|have been)\s+"
        r"(?:successfully\s+)?exploited\b",
        re.I,
    ),
    re.compile(
        r"\b(?:the\s+)?attacker\s+(?:gained|obtained|achieved)\s+access\b",
        re.I,
    ),
    re.compile(
        r"\b(?:credentials|secrets|data)\s+"
        r"(?:were|was|have been|has been)\s+(?:stolen|exfiltrated)\b",
        re.I,
    ),
)
_NEGATION = re.compile(
    r"\b(?:no|not|never|cannot|can't|does not|doesn't|did not|didn't|"
    r"unconfirmed|unknown|without evidence|no evidence)\b",
    re.I,
)


class _BoundaryError(ValueError):
    """Raised when data cannot safely cross the AI boundary."""


class _IncompleteResponse(_BoundaryError):
    """Raised when the API safely reports an incomplete response."""

    def __init__(self, reason: str) -> None:
        super().__init__("model response was incomplete")
        self.reason = reason


class _ResponseSchemaError(_BoundaryError):
    """Raised when model output cannot satisfy the structured-output contract."""


class _ReferenceValidationError(_BoundaryError):
    """Raised when model output references evidence outside the allowlist."""


class _SafetyValidationError(_BoundaryError):
    """Raised when model output makes a prohibited incident claim."""


def sanitized_ai_error(
    code: str,
    *,
    reason: Any = None,
) -> dict[str, str]:
    """Build a canonical error without retaining untrusted diagnostic text."""

    canonical_code = code if code in _ERROR_DETAILS else API_FAILED
    stage, message = _ERROR_DETAILS[canonical_code]
    error = {
        "stage": stage,
        "code": canonical_code,
        "message": message,
    }
    if canonical_code == INCOMPLETE_RESPONSE:
        safe_reason = reason if reason in _KNOWN_INCOMPLETE_REASONS else "unknown"
        error["reason"] = safe_reason
    return error


def normalize_ai_error(value: Any) -> dict[str, str]:
    """Reduce an analyst-supplied error to the public allowlisted contract."""

    if not isinstance(value, Mapping):
        return sanitized_ai_error(API_FAILED)
    return sanitized_ai_error(value.get("code"), reason=value.get("reason"))


def _clean_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _BoundaryError(f"{field_name} must be a non-empty string")
    normalized = unicodedata.normalize("NFKC", value)
    normalized = "".join(
        character
        for character in normalized
        if not unicodedata.category(character).startswith("C")
    )
    normalized = " ".join(normalized.split())
    for pattern in _SENSITIVE_PATTERNS:
        normalized = pattern.sub("[REDACTED]", normalized)
    normalized = normalized[:MAX_TEXT_CHARS].strip()
    if not normalized:
        raise _BoundaryError(f"{field_name} was empty after sanitization")
    return normalized


def _clean_optional_text_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _BoundaryError(f"{field_name} must be a list")
    cleaned: list[str] = []
    for index, item in enumerate(value[:MAX_LIST_ITEMS]):
        cleaned.append(_clean_text(item, f"{field_name}[{index}]"))
    return cleaned


def _score(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
        raise _BoundaryError(f"{field_name} must be an integer from 0 to 100")
    return value


def _sequence(value: Any, field_name: str) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        raise _BoundaryError(f"{field_name} must be an iterable")
    return list(value)


def _confirmed_finding_records(
    report: Mapping[str, Any],
) -> list[tuple[int, str, str, Mapping[str, Any]]]:
    raw_findings = _sequence(report.get("findings", []), "findings")
    records: list[tuple[int, str, str, Mapping[str, Any]]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_findings):
        if not isinstance(raw, Mapping):
            raise _BoundaryError(f"findings[{index}] must be an object")
        if raw.get("status") != "CONFIRMED":
            continue
        finding_id = raw.get("finding_id")
        severity = raw.get("severity")
        if not isinstance(finding_id, str) or not _FINDING_ID.fullmatch(finding_id):
            raise _BoundaryError(f"findings[{index}].finding_id is invalid")
        if finding_id in seen:
            raise _BoundaryError("confirmed finding IDs must be unique")
        if severity not in _SEVERITIES:
            raise _BoundaryError(f"findings[{index}].severity is invalid")
        seen.add(finding_id)
        records.append((index, finding_id, severity, raw))
    return records


def _confirmed_findings(
    records: list[tuple[int, str, str, Mapping[str, Any]]],
    *,
    required_ids: Iterable[str] = (),
) -> list[dict[str, Any]]:
    required = set(required_ids)
    known_ids = {finding_id for _, finding_id, _, _ in records}
    if not required.issubset(known_ids):
        raise _BoundaryError("required attack-path findings are unavailable")
    if len(required) > MAX_FINDINGS:
        raise _BoundaryError("attack-path findings exceeded the finding limit")

    selected_ids = set(required)
    for _, finding_id, _, _ in records:
        if len(selected_ids) >= MAX_FINDINGS:
            break
        selected_ids.add(finding_id)

    findings: list[dict[str, Any]] = []
    for index, finding_id, severity, raw in records:
        if finding_id not in selected_ids:
            continue
        findings.append(
            {
                "finding_id": finding_id,
                "status": "CONFIRMED",
                "title": _clean_text(raw.get("title"), f"findings[{index}].title"),
                "score": _score(raw.get("score"), f"findings[{index}].score"),
                "severity": severity,
                "risk_factors": _clean_optional_text_list(
                    raw.get("risk_factors"), f"findings[{index}].risk_factors"
                ),
                "recommendations": _clean_optional_text_list(
                    raw.get("recommendations"), f"findings[{index}].recommendations"
                ),
                "limitations": _clean_optional_text_list(
                    raw.get("limitations"), f"findings[{index}].limitations"
                ),
            }
        )
    return findings


def _plausible_attack_paths(
    raw_paths: list[Any], *, known_finding_ids: set[str]
) -> tuple[list[dict[str, Any]], list[str]]:
    paths: list[dict[str, Any]] = []
    seen: set[str] = set()
    required_finding_ids: list[str] = []
    required_finding_id_set: set[str] = set()
    for index, raw in enumerate(raw_paths):
        if not isinstance(raw, Mapping):
            raise _BoundaryError(f"attack_paths[{index}] must be an object")
        if raw.get("status") != "PLAUSIBLE":
            continue
        path_id = raw.get("attack_path_id")
        severity = raw.get("severity")
        if not isinstance(path_id, str) or not _ATTACK_PATH_ID.fullmatch(path_id):
            raise _BoundaryError(f"attack_paths[{index}].attack_path_id is invalid")
        if path_id in seen:
            raise _BoundaryError("attack path IDs must be unique")
        if severity not in _SEVERITIES:
            raise _BoundaryError(f"attack_paths[{index}].severity is invalid")
        supporting = raw.get("supporting_finding_ids")
        if not isinstance(supporting, list) or not supporting:
            raise _BoundaryError(
                f"attack_paths[{index}].supporting_finding_ids must be a non-empty list"
            )
        if not all(
            isinstance(item, str)
            and _FINDING_ID.fullmatch(item)
            and item in known_finding_ids
            for item in supporting
        ):
            raise _BoundaryError(
                f"attack_paths[{index}] references an unknown confirmed finding"
            )
        seen.add(path_id)
        retained_supporting = supporting[:MAX_LIST_ITEMS]
        candidate_required = required_finding_id_set | set(retained_supporting)
        if len(candidate_required) > MAX_FINDINGS:
            continue
        paths.append(
            {
                "attack_path_id": path_id,
                "status": "PLAUSIBLE",
                "title": _clean_text(raw.get("title"), f"attack_paths[{index}].title"),
                "score": _score(raw.get("score"), f"attack_paths[{index}].score"),
                "severity": severity,
                "supporting_finding_ids": retained_supporting,
                "risk_factors": _clean_optional_text_list(
                    raw.get("risk_factors"), f"attack_paths[{index}].risk_factors"
                ),
                "explanation": _clean_text(
                    raw.get("explanation"), f"attack_paths[{index}].explanation"
                ),
                "limitations": _clean_optional_text_list(
                    raw.get("limitations"), f"attack_paths[{index}].limitations"
                ),
            }
        )
        for finding_id in retained_supporting:
            if finding_id not in required_finding_id_set:
                required_finding_ids.append(finding_id)
                required_finding_id_set.add(finding_id)
        if len(paths) >= MAX_ATTACK_PATHS:
            break
    return paths, required_finding_ids


def _evidence_gaps(report: Mapping[str, Any]) -> list[dict[str, str]]:
    raw_gaps = _sequence(report.get("evidence_gaps", []), "evidence_gaps")
    gaps: list[dict[str, str]] = []
    for index, raw in enumerate(raw_gaps[:MAX_EVIDENCE_GAPS]):
        if not isinstance(raw, Mapping):
            raise _BoundaryError(f"evidence_gaps[{index}] must be an object")
        gaps.append(
            {
                "component": _clean_text(
                    raw.get("component"), f"evidence_gaps[{index}].component"
                ),
                "stage": _clean_text(
                    raw.get("stage"), f"evidence_gaps[{index}].stage"
                ),
                "status": _clean_text(
                    raw.get("status"), f"evidence_gaps[{index}].status"
                ),
            }
        )
    return gaps


def _payload(
    report: Mapping[str, Any], raw_paths: list[Any]
) -> tuple[dict[str, Any], set[str], set[str]]:
    finding_records = _confirmed_finding_records(report)
    all_finding_ids = {finding_id for _, finding_id, _, _ in finding_records}
    paths, required_finding_ids = _plausible_attack_paths(
        raw_paths, known_finding_ids=all_finding_ids
    )
    findings = _confirmed_findings(
        finding_records, required_ids=required_finding_ids
    )
    finding_ids = {item["finding_id"] for item in findings}
    path_ids = {item["attack_path_id"] for item in paths}
    payload = {
        "confirmed_findings": findings,
        "plausible_attack_paths": paths,
        "evidence_gaps": _evidence_gaps(report),
    }
    return payload, finding_ids, path_ids


def _load_schema(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as source:
            schema = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        raise _BoundaryError(f"unable to load AI analysis schema: {path}") from exc
    if not isinstance(schema, dict):
        raise _BoundaryError("AI analysis schema must be an object")
    Draft202012Validator.check_schema(schema)
    return schema


def _output_text(response: Any) -> str:
    status = (
        response.get("status")
        if isinstance(response, Mapping)
        else getattr(response, "status", None)
    )
    if status == "incomplete":
        details = (
            response.get("incomplete_details")
            if isinstance(response, Mapping)
            else getattr(response, "incomplete_details", None)
        )
        reason = (
            details.get("reason")
            if isinstance(details, Mapping)
            else getattr(details, "reason", None)
        )
        safe_reason = reason if reason in _KNOWN_INCOMPLETE_REASONS else "unknown"
        raise _IncompleteResponse(safe_reason)
    if status is not None and status != "completed":
        raise _BoundaryError("model response did not complete")
    value = (
        response.get("output_text")
        if isinstance(response, Mapping)
        else getattr(response, "output_text", None)
    )
    if not isinstance(value, str) or not value.strip():
        raise _ResponseSchemaError("model response did not contain output_text")
    if len(value) > MAX_MODEL_OUTPUT_CHARS:
        raise _ResponseSchemaError("model response exceeded the output limit")
    return value


def _all_text_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for nested in value.values():
            yield from _all_text_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _all_text_values(nested)


def _validate_no_incident_claims(analysis: Mapping[str, Any]) -> None:
    for text in _all_text_values(analysis):
        for sentence in re.split(r"(?<=[.!?])\s+|[\r\n]+", text):
            if _NEGATION.search(sentence):
                continue
            if any(pattern.search(sentence) for pattern in _ASSERTIVE_INCIDENT_PATTERNS):
                raise _SafetyValidationError(
                    "model output asserted exploitation or compromise as fact"
                )


def _validate_references(
    analysis: Mapping[str, Any], *, finding_ids: set[str], path_ids: set[str]
) -> None:
    known_ids = finding_ids | path_ids
    for text in _all_text_values(analysis):
        for referenced_id in _ANY_EVIDENCE_ID.findall(text):
            if referenced_id not in known_ids:
                raise _ReferenceValidationError(
                    f"model output referenced unknown ID {referenced_id}"
                )

    explained: set[str] = set()
    for item in analysis["attack_path_explanations"]:
        path_id = item["attack_path_id"]
        if path_id not in path_ids or path_id in explained:
            raise _ReferenceValidationError(
                "attack path explanations contain an invalid reference"
            )
        explained.add(path_id)

    priorities = analysis["priority_order"]
    positions = [item["position"] for item in priorities]
    if positions != list(range(1, len(priorities) + 1)):
        raise _ReferenceValidationError(
            "priority positions must be unique and contiguous"
        )
    priority_ids: set[str] = set()
    for item in priorities:
        reference_id = item["reference_id"]
        expected = finding_ids if item["reference_type"] == "finding" else path_ids
        if reference_id not in expected or reference_id in priority_ids:
            raise _ReferenceValidationError(
                "priority order contains an invalid reference"
            )
        priority_ids.add(reference_id)

    for section in ("remediation_steps", "operator_review_notes"):
        for item in analysis[section]:
            referenced_findings = item["finding_ids"]
            referenced_paths = item["attack_path_ids"]
            if not referenced_findings and not referenced_paths:
                raise _ReferenceValidationError(
                    f"{section} item is not tied to existing evidence"
                )
            if not set(referenced_findings).issubset(finding_ids):
                raise _ReferenceValidationError(
                    f"{section} referenced an unknown finding"
                )
            if not set(referenced_paths).issubset(path_ids):
                raise _ReferenceValidationError(
                    f"{section} referenced an unknown attack path"
                )


def _safe_result(
    *,
    status: str,
    report: Any,
    attack_paths: list[Any],
    analysis: dict[str, Any] | None = None,
    error: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "deterministic_report": deepcopy(report),
        "attack_paths": deepcopy(attack_paths),
        "analysis": deepcopy(analysis),
        "error": deepcopy(dict(error)) if error is not None else None,
    }


def _new_openai_client() -> Any:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise _BoundaryError("OPENAI_API_KEY is not configured")
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise _BoundaryError("the OpenAI Python package is not installed") from exc
    return OpenAI(api_key=api_key)


class EvidenceGroundedAnalyst:
    """Explain deterministic evidence without gaining authority over it."""

    def __init__(
        self,
        *,
        client: Any | None = None,
        schema_path: str | Path | None = None,
    ) -> None:
        self._client = client
        self.schema_path = Path(schema_path or DEFAULT_SCHEMA_PATH)

    def analyze(
        self,
        deterministic_report: Mapping[str, Any],
        attack_paths: Iterable[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Return analysis plus an unchanged copy of all deterministic inputs.

        Empty evidence is skipped before client creation, so it requires neither an
        API key nor the OpenAI package. All API, parsing, schema, and safety failures
        are converted to ``AI_ANALYSIS_FAILED``.
        """

        report_copy: Any = deepcopy(deterministic_report)
        try:
            if not isinstance(deterministic_report, Mapping):
                raise _BoundaryError("deterministic_report must be an object")
            source_paths = (
                deterministic_report.get("attack_paths", [])
                if attack_paths is None
                else attack_paths
            )
            raw_paths = _sequence(source_paths, "attack_paths")
        except Exception:
            return _safe_result(
                status=AI_ANALYSIS_FAILED,
                report=report_copy,
                attack_paths=[],
                error=sanitized_ai_error(CONFIGURATION_FAILED),
            )

        try:
            payload, finding_ids, path_ids = _payload(deterministic_report, raw_paths)
            if not payload["confirmed_findings"] and not payload["plausible_attack_paths"]:
                return _safe_result(
                    status=AI_ANALYSIS_SKIPPED,
                    report=report_copy,
                    attack_paths=raw_paths,
                )

            schema = _load_schema(self.schema_path)
            model_input = build_analysis_input(payload)
            if len(model_input) > MAX_MODEL_INPUT_CHARS:
                raise _BoundaryError("sanitized model input exceeded the input limit")

            client = self._client or _new_openai_client()
            model = (
                os.environ.get("OPENAI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
            )
            api_schema = {
                key: value
                for key, value in schema.items()
                if key not in {"$schema", "$id", "title"}
            }
        except Exception:
            return _safe_result(
                status=AI_ANALYSIS_FAILED,
                report=report_copy,
                attack_paths=raw_paths,
                error=sanitized_ai_error(CONFIGURATION_FAILED),
            )

        try:
            response = client.responses.create(
                model=model,
                instructions=SYSTEM_PROMPT,
                input=model_input,
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "evidence_grounded_ai_analysis",
                        "strict": True,
                        "schema": api_schema,
                    }
                },
                tools=[],
                tool_choice="none",
                store=False,
                max_output_tokens=MAX_OUTPUT_TOKENS,
            )
        except Exception:
            return _safe_result(
                status=AI_ANALYSIS_FAILED,
                report=report_copy,
                attack_paths=raw_paths,
                error=sanitized_ai_error(API_FAILED),
            )

        try:
            output_text = _output_text(response)
        except _IncompleteResponse as exc:
            return _safe_result(
                status=AI_ANALYSIS_FAILED,
                report=report_copy,
                attack_paths=raw_paths,
                error=sanitized_ai_error(
                    INCOMPLETE_RESPONSE,
                    reason=exc.reason,
                ),
            )
        except _ResponseSchemaError:
            return _safe_result(
                status=AI_ANALYSIS_FAILED,
                report=report_copy,
                attack_paths=raw_paths,
                error=sanitized_ai_error(SCHEMA_VALIDATION_FAILED),
            )
        except Exception:
            return _safe_result(
                status=AI_ANALYSIS_FAILED,
                report=report_copy,
                attack_paths=raw_paths,
                error=sanitized_ai_error(API_FAILED),
            )

        try:
            output = json.loads(output_text)
            if not isinstance(output, dict):
                raise _ResponseSchemaError("model output must be a JSON object")
            Draft202012Validator(schema).validate(output)
        except Exception:
            return _safe_result(
                status=AI_ANALYSIS_FAILED,
                report=report_copy,
                attack_paths=raw_paths,
                error=sanitized_ai_error(SCHEMA_VALIDATION_FAILED),
            )

        try:
            _validate_references(output, finding_ids=finding_ids, path_ids=path_ids)
        except Exception:
            return _safe_result(
                status=AI_ANALYSIS_FAILED,
                report=report_copy,
                attack_paths=raw_paths,
                error=sanitized_ai_error(REFERENCE_VALIDATION_FAILED),
            )

        try:
            _validate_no_incident_claims(output)
        except Exception:
            return _safe_result(
                status=AI_ANALYSIS_FAILED,
                report=report_copy,
                attack_paths=raw_paths,
                error=sanitized_ai_error(SAFETY_VALIDATION_FAILED),
            )
        return _safe_result(
            status=AI_ANALYSIS_COMPLETE,
            report=report_copy,
            attack_paths=raw_paths,
            analysis=output,
        )

    run = analyze


AIAnalyst = EvidenceGroundedAnalyst


def analyze_report(
    deterministic_report: Mapping[str, Any],
    attack_paths: Iterable[Mapping[str, Any]] | None = None,
    *,
    client: Any | None = None,
    schema_path: str | Path | None = None,
) -> dict[str, Any]:
    """Functional entry point for evidence-grounded analysis."""

    return EvidenceGroundedAnalyst(
        client=client, schema_path=schema_path
    ).analyze(deterministic_report, attack_paths)


__all__ = [
    "API_FAILED",
    "AI_ANALYSIS_COMPLETE",
    "AI_ANALYSIS_FAILED",
    "AI_ANALYSIS_SKIPPED",
    "AIAnalyst",
    "CONFIGURATION_FAILED",
    "DEFAULT_MODEL",
    "DEFAULT_SCHEMA_PATH",
    "EvidenceGroundedAnalyst",
    "INCOMPLETE_RESPONSE",
    "REFERENCE_VALIDATION_FAILED",
    "SAFETY_VALIDATION_FAILED",
    "SCHEMA_VALIDATION_FAILED",
    "analyze_report",
    "normalize_ai_error",
    "sanitized_ai_error",
]
