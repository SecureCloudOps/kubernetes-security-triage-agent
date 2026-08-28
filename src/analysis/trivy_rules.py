"""Deterministic findings from normalized Trivy vulnerability evidence.

The engine performs no AI or network operations. Standalone vulnerability
scores come directly from ``vulnerability_scores``; the ``critical_cve`` and
``high_cve`` weights are retained only as attack-path correlation metadata.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from src.collectors.trivy import EVIDENCE_SOURCE
from src.models import ScanResult, ScanStatus

DEFAULT_RISK_RULES_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "risk-rules.yaml"
)
DEFAULT_FINDING_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "schemas" / "finding.schema.json"
)

_SUPPORTED_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"})
_CORRELATION_FACTORS = {
    "CRITICAL": "critical_cve",
    "HIGH": "high_cve",
}


def deterministic_trivy_finding_id(
    *,
    cluster: str,
    namespace: str,
    kind: str,
    workload: str,
    image: str,
    vulnerability_id: str,
    package_name: str,
    installed_version: str,
) -> str:
    """Return a stable ID for one workload vulnerability identity."""

    identity = json.dumps(
        [
            cluster,
            namespace,
            kind,
            workload,
            image,
            vulnerability_id,
            package_name,
            installed_version,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"KSA-{hashlib.sha256(identity).hexdigest()[:12]}"


def _load_mapping(path: Path, key: str) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as source:
            config = yaml.safe_load(source)
    except OSError as exc:
        raise ValueError(f"unable to read risk rules config: {path}") from exc
    if not isinstance(config, Mapping):
        raise ValueError("risk rules config must be an object")
    value = config.get(key)
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"risk rules config requires a non-empty {key} mapping")
    return dict(value)


def _integer_mapping(path: Path, key: str) -> dict[str, int]:
    value = _load_mapping(path, key)
    if not all(
        isinstance(name, str)
        and isinstance(score, int)
        and not isinstance(score, bool)
        and 0 <= score <= 100
        for name, score in value.items()
    ):
        raise ValueError(
            f"risk rules config {key} values must be integers from 0 to 100"
        )
    return value


def _load_schema(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as source:
            schema = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read finding schema: {path}") from exc
    if not isinstance(schema, dict):
        raise ValueError("finding schema must be an object")
    Draft202012Validator.check_schema(schema)
    return schema


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _optional_text(value: Any, field_name: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string when present")
    return value


def _canonical_evidence(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {
        json.dumps(
            item, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ): item
        for item in items
    }
    return [deepcopy(unique[key]) for key in sorted(unique)]


def _collection_status_evidence(scan: ScanResult, reason: str) -> dict[str, Any]:
    return {
        "source": f"{EVIDENCE_SOURCE}.collection_status",
        "observed_at": "1970-01-01T00:00:00Z",
        "collector_version": "unavailable",
        "details": {
            "workload": scan.target.to_dict(),
            "collection_status": scan.status.value,
            "errors": scan.errors.copy(),
            "observation_available": False,
            "reason": reason,
        },
    }


class TrivyRuleEngine:
    """Convert complete Trivy scan results into one finding per unique CVE."""

    def __init__(
        self,
        *,
        config_path: str | Path | None = None,
        schema_path: str | Path | None = None,
    ) -> None:
        self.config_path = Path(config_path or DEFAULT_RISK_RULES_PATH)
        self.schema_path = Path(schema_path or DEFAULT_FINDING_SCHEMA_PATH)
        self.vulnerability_scores = _integer_mapping(
            self.config_path, "vulnerability_scores"
        )
        if set(self.vulnerability_scores) != _SUPPORTED_SEVERITIES:
            raise ValueError(
                "vulnerability_scores must define exactly: "
                + ", ".join(sorted(_SUPPORTED_SEVERITIES))
            )

        weights = _integer_mapping(self.config_path, "weights")
        missing = sorted(set(_CORRELATION_FACTORS.values()).difference(weights))
        if missing:
            raise ValueError(
                "risk rules config is missing correlation weights: "
                + ", ".join(missing)
            )
        self.correlation_weights = {
            name: weights[name] for name in _CORRELATION_FACTORS.values()
        }

        self._validator = Draft202012Validator(
            _load_schema(self.schema_path), format_checker=FormatChecker()
        )

    def analyze(
        self,
        scans: (
            ScanResult
            | Mapping[str, Any]
            | Iterable[ScanResult | Mapping[str, Any]]
        ),
    ) -> list[dict[str, Any]]:
        """Analyze scan results without treating failed or partial scans as clean."""

        if isinstance(scans, ScanResult):
            raw_scans: Iterable[ScanResult | Mapping[str, Any]] = [scans]
        elif isinstance(scans, Mapping) and self._is_scan_result_mapping(scans):
            raw_scans = [scans]
        elif isinstance(scans, Mapping):
            raise TypeError("scans must contain ScanResult objects or mappings")
        else:
            raw_scans = scans

        results_by_id: dict[str, dict[str, Any]] = {}
        evidence_by_id: dict[str, list[dict[str, Any]]] = {}
        for raw_scan in raw_scans:
            scan = (
                raw_scan
                if isinstance(raw_scan, ScanResult)
                else ScanResult.from_dict(raw_scan)
                if isinstance(raw_scan, Mapping)
                and self._is_scan_result_mapping(raw_scan)
                else None
            )
            if scan is None:
                raise TypeError("scans must contain ScanResult objects or mappings")

            scan_results = self._analyze_scan(scan)
            for result in scan_results:
                finding_id = result["finding_id"]
                if finding_id not in results_by_id:
                    results_by_id[finding_id] = result
                    evidence_by_id[finding_id] = result["evidence"]
                else:
                    evidence_by_id[finding_id].extend(result["evidence"])

        for finding_id, result in results_by_id.items():
            result["evidence"] = _canonical_evidence(evidence_by_id[finding_id])
            self._validator.validate(result)

        return sorted(
            results_by_id.values(),
            key=lambda result: (
                result["target"]["cluster"],
                result["target"]["namespace"],
                result["target"]["kind"],
                result["target"]["name"],
                result["finding_id"],
            ),
        )

    evaluate = analyze

    @staticmethod
    def _is_scan_result_mapping(value: Mapping[str, Any]) -> bool:
        return {"target", "status", "evidence"}.issubset(value)

    def _analyze_scan(self, scan: ScanResult) -> list[dict[str, Any]]:
        matching_evidence = [
            item.to_dict() for item in scan.evidence if item.source == EVIDENCE_SOURCE
        ]
        if scan.status is not ScanStatus.COMPLETE:
            evidence = matching_evidence + [
                _collection_status_evidence(scan, "Trivy scan was not complete.")
            ]
            return [self._insufficient_evidence(scan, evidence)]

        occurrences: dict[
            tuple[str, str, str, str], list[tuple[dict[str, Any], dict[str, Any]]]
        ] = {}
        try:
            for evidence in matching_evidence:
                details = evidence.get("details")
                if not isinstance(details, Mapping):
                    raise ValueError("Trivy evidence details must be an object")
                image = _required_text(
                    details.get("image_reference"), "image_reference"
                )
                vulnerabilities = details.get("vulnerabilities")
                if not isinstance(vulnerabilities, list):
                    raise ValueError("vulnerabilities must be a list")
                count = details.get("vulnerability_count")
                if (
                    isinstance(count, bool)
                    or not isinstance(count, int)
                    or count != len(vulnerabilities)
                ):
                    raise ValueError("vulnerability_count must match vulnerabilities")

                for index, raw_vulnerability in enumerate(vulnerabilities):
                    vulnerability = self._normalize_vulnerability(
                        raw_vulnerability, index=index
                    )
                    key = (
                        image,
                        vulnerability["vulnerability_id"],
                        vulnerability["package_name"],
                        vulnerability["installed_version"],
                    )
                    occurrences.setdefault(key, []).append((vulnerability, evidence))
        except (TypeError, ValueError) as exc:
            evidence = matching_evidence + [
                _collection_status_evidence(
                    scan, f"Trivy evidence was incomplete or invalid: {exc}"
                )
            ]
            return [self._insufficient_evidence(scan, evidence)]

        findings: list[dict[str, Any]] = []
        for key in sorted(occurrences):
            entries = occurrences[key]
            # Canonical ordering makes conflict handling independent of input order.
            vulnerability, _ = min(
                entries,
                key=lambda entry: json.dumps(
                    entry[0], ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ),
            )
            evidence = _canonical_evidence(item for _, item in entries)
            finding = self._finding(scan, key[0], vulnerability, evidence)
            self._validator.validate(finding)
            findings.append(finding)
        return findings

    def _normalize_vulnerability(
        self, value: Any, *, index: int
    ) -> dict[str, str | None]:
        if not isinstance(value, Mapping):
            raise ValueError(f"vulnerabilities[{index}] must be an object")
        severity = _required_text(
            value.get("severity"), f"vulnerabilities[{index}].severity"
        ).upper()
        if severity not in self.vulnerability_scores:
            raise ValueError(f"unsupported Trivy severity: {severity}")
        return {
            "vulnerability_id": _required_text(
                value.get("vulnerability_id"),
                f"vulnerabilities[{index}].vulnerability_id",
            ),
            "severity": severity,
            "package_name": _required_text(
                value.get("package_name"), f"vulnerabilities[{index}].package_name"
            ),
            "installed_version": _required_text(
                value.get("installed_version"),
                f"vulnerabilities[{index}].installed_version",
            ),
            "fixed_version": _optional_text(
                value.get("fixed_version"), f"vulnerabilities[{index}].fixed_version"
            ),
            "title": _optional_text(
                value.get("title"), f"vulnerabilities[{index}].title"
            ),
            "reference": _optional_text(
                value.get("reference"), f"vulnerabilities[{index}].reference"
            ),
        }

    def _finding(
        self,
        scan: ScanResult,
        image: str,
        vulnerability: Mapping[str, str | None],
        evidence: list[dict[str, Any]],
    ) -> dict[str, Any]:
        severity = str(vulnerability["severity"])
        vulnerability_id = str(vulnerability["vulnerability_id"])
        package_name = str(vulnerability["package_name"])
        installed_version = str(vulnerability["installed_version"])
        fixed_version = vulnerability["fixed_version"]
        target = scan.target.to_dict()

        if fixed_version:
            recommendations = [
                f"Upgrade {package_name} from {installed_version} to fixed version "
                f"{fixed_version} in {image}."
            ]
        else:
            recommendations = [
                f"No fixed version is reported by Trivy for {package_name}. Monitor "
                "the vendor advisory and reduce exposure until a fix is available."
            ]

        correlation_factor = _CORRELATION_FACTORS.get(severity)
        return {
            "finding_id": deterministic_trivy_finding_id(
                cluster=scan.target.cluster,
                namespace=scan.target.namespace,
                kind=scan.target.kind,
                workload=scan.target.name,
                image=image,
                vulnerability_id=vulnerability_id,
                package_name=package_name,
                installed_version=installed_version,
            ),
            "title": f"{vulnerability_id} affects {package_name} in {image}",
            "status": "CONFIRMED",
            # The finding schema uses lowercase severities. This is a direct,
            # lossless representation of Trivy's normalized uppercase value.
            "severity": severity.lower() if severity != "UNKNOWN" else "info",
            "score": self.vulnerability_scores[severity],
            "confidence": "high",
            "target": target,
            "evidence": evidence,
            "risk_factors": [correlation_factor] if correlation_factor else [],
            "attack_path": None,
            "blast_radius": None,
            "recommendations": recommendations,
            "limitations": [
                "Trivy identified the package vulnerability in the image; this "
                "does not establish runtime reachability or exploitability."
            ],
        }

    def _insufficient_evidence(
        self, scan: ScanResult, evidence: Iterable[dict[str, Any]]
    ) -> dict[str, Any]:
        target = scan.target.to_dict()
        finding = {
            "finding_id": deterministic_trivy_finding_id(
                cluster=scan.target.cluster,
                namespace=scan.target.namespace,
                kind=scan.target.kind,
                workload=scan.target.name,
                image="insufficient_evidence",
                vulnerability_id="insufficient_evidence",
                package_name="insufficient_evidence",
                installed_version="insufficient_evidence",
            ),
            "title": "Container vulnerability scan was incomplete",
            "status": "INSUFFICIENT_EVIDENCE",
            "severity": "info",
            "score": 0,
            "confidence": "low",
            "target": target,
            "evidence": _canonical_evidence(evidence),
            "risk_factors": [],
            "attack_path": None,
            "blast_radius": None,
            "recommendations": [
                "Complete a successful Trivy vulnerability scan before assessing "
                "the workload image."
            ],
            "limitations": [
                "The available scan did not provide complete vulnerability evidence."
            ],
        }
        self._validator.validate(finding)
        return finding


def analyze_trivy(
    scans: ScanResult | Mapping[str, Any] | Iterable[ScanResult | Mapping[str, Any]],
    *,
    config_path: str | Path | None = None,
    schema_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Convenience wrapper for :class:`TrivyRuleEngine`."""

    return TrivyRuleEngine(
        config_path=config_path, schema_path=schema_path
    ).analyze(scans)


evaluate_trivy = analyze_trivy

__all__ = [
    "TrivyRuleEngine",
    "analyze_trivy",
    "deterministic_trivy_finding_id",
    "evaluate_trivy",
]
