"""Deterministic rules for normalized Kubernetes exposure evidence.

The engine performs no network access and uses no AI.  It produces at most
one result for each workload, retaining every normalized Service and Ingress
observation that supports the result.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from src.collectors.exposure import EVIDENCE_SOURCE, ExposureClassification
from src.models import Evidence

DEFAULT_RISK_RULES_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "risk-rules.yaml"
)

_CLASSIFICATION_RANK = {
    ExposureClassification.UNKNOWN: 0,
    ExposureClassification.INTERNAL: 1,
    ExposureClassification.POTENTIALLY_EXTERNAL: 2,
    ExposureClassification.CONFIRMED_EXTERNAL: 3,
}


def deterministic_exposure_finding_id(
    *, cluster: str, namespace: str, kind: str, workload: str, rule_id: str
) -> str:
    """Return a stable hexadecimal ID for one workload exposure result."""

    identity = json.dumps(
        [cluster, namespace, kind, workload, rule_id],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"KSA-{hashlib.sha256(identity).hexdigest()[:12]}"


def _load_config(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as config_file:
            config = yaml.safe_load(config_file)
    except OSError as exc:
        raise ValueError(f"unable to read risk rules config: {path}") from exc

    if not isinstance(config, dict):
        raise ValueError("risk rules config must be an object")
    return config


def _integer_mapping(config: Mapping[str, Any], key: str) -> dict[str, int]:
    value = config.get(key)
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"risk rules config requires a non-empty {key} mapping")
    if not all(
        isinstance(name, str)
        and isinstance(number, int)
        and not isinstance(number, bool)
        for name, number in value.items()
    ):
        raise ValueError(f"risk rules config {key} values must be integers")
    return dict(value)


def _evidence_dict(item: Evidence | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(item, Evidence):
        return item.to_dict()
    if isinstance(item, Mapping):
        return deepcopy(dict(item))
    raise TypeError("evidence must contain Evidence objects or mappings")


def _required_target(
    details: Mapping[str, Any],
) -> dict[str, str | None] | None:
    workload = details.get("workload")
    if not isinstance(workload, Mapping):
        return None

    target: dict[str, str | None] = {
        "cluster": workload.get("cluster"),
        "namespace": workload.get("namespace"),
        "kind": workload.get("kind"),
        "name": workload.get("name"),
        "container": None,
    }
    if not all(
        isinstance(value, str) and value.strip()
        for key, value in target.items()
        if key != "container"
    ):
        return None
    return target


def _canonical_evidence(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate exact observations and return them in a stable order."""

    unique = {
        json.dumps(
            item,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ): item
        for item in items
    }
    return [deepcopy(unique[key]) for key in sorted(unique)]


class ExposureRuleEngine:
    """Convert workload exposure evidence into deterministic results."""

    def __init__(self, *, config_path: str | Path | None = None) -> None:
        self.config_path = Path(config_path or DEFAULT_RISK_RULES_PATH)
        config = _load_config(self.config_path)
        self.weights = _integer_mapping(config, "weights")
        self.severity_thresholds = _integer_mapping(config, "severity_thresholds")

        limits = _integer_mapping(config, "score_limits")
        self.minimum_score = limits.get("minimum", 0)
        self.maximum_score = min(limits.get("maximum", 100), 100)
        if self.minimum_score < 0 or self.minimum_score > self.maximum_score:
            raise ValueError("score_limits must define 0 <= minimum <= maximum <= 100")

        required_weights = {"public_exposure", "potential_external_exposure"}
        missing_weights = sorted(required_weights.difference(self.weights))
        if missing_weights:
            raise ValueError(
                "risk rules config is missing weights: " + ", ".join(missing_weights)
            )

    def analyze(
        self, evidence: Iterable[Evidence | Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        """Return no more than one exposure result for each workload."""

        if isinstance(evidence, (Evidence, Mapping)):
            raise TypeError("evidence must be an iterable of evidence items")

        grouped: dict[
            tuple[str, str, str, str],
            dict[str, Any],
        ] = {}
        for raw_item in evidence:
            item = _evidence_dict(raw_item)
            if item.get("source") != EVIDENCE_SOURCE:
                continue
            details = item.get("details")
            if not isinstance(details, Mapping):
                continue

            target = _required_target(details)
            if target is None:
                continue
            try:
                classification = ExposureClassification(details.get("classification"))
            except (TypeError, ValueError):
                continue

            key = (
                str(target["cluster"]),
                str(target["namespace"]),
                str(target["kind"]),
                str(target["name"]),
            )
            group = grouped.setdefault(
                key,
                {
                    "target": target,
                    "classification": ExposureClassification.UNKNOWN,
                    "evidence": [],
                },
            )
            group["evidence"].append(item)
            if _CLASSIFICATION_RANK[classification] > _CLASSIFICATION_RANK[
                group["classification"]
            ]:
                group["classification"] = classification

        results = [
            result
            for group in grouped.values()
            if (result := self._result(group)) is not None
        ]
        return sorted(
            results,
            key=lambda result: (
                result["target"]["cluster"],
                result["target"]["namespace"],
                result["target"]["kind"],
                result["target"]["name"],
                result["finding_id"],
            ),
        )

    evaluate = analyze

    def _result(self, group: Mapping[str, Any]) -> dict[str, Any] | None:
        classification = group["classification"]
        if classification is ExposureClassification.INTERNAL:
            return None

        target = deepcopy(group["target"])
        evidence = _canonical_evidence(group["evidence"])
        if classification is ExposureClassification.CONFIRMED_EXTERNAL:
            return self._finding(
                target=target,
                evidence=evidence,
                rule_id="confirmed_external",
                risk_factor="public_exposure",
                title="Workload has confirmed public exposure",
                status="CONFIRMED",
                confidence="high",
                recommendation=(
                    "Restrict the public Service or Ingress unless external access "
                    "is required."
                ),
                limitation=(
                    "This finding confirms a public endpoint, not successful access "
                    "or exploitation."
                ),
            )
        if classification is ExposureClassification.POTENTIALLY_EXTERNAL:
            return self._finding(
                target=target,
                evidence=evidence,
                rule_id="potentially_external",
                risk_factor="potential_external_exposure",
                title="Workload may be externally reachable",
                status="CONFIRMED",
                confidence="medium",
                recommendation=(
                    "Verify the Service or Ingress endpoint and restrict it if "
                    "external access is not required."
                ),
                limitation="External reachability is possible but is not confirmed.",
            )
        return self._insufficient_evidence(target=target, evidence=evidence)

    def _finding(
        self,
        *,
        target: dict[str, str | None],
        evidence: list[dict[str, Any]],
        rule_id: str,
        risk_factor: str,
        title: str,
        status: str,
        confidence: str,
        recommendation: str,
        limitation: str,
    ) -> dict[str, Any]:
        score = max(
            self.minimum_score,
            min(self.weights[risk_factor], self.maximum_score, 100),
        )
        return {
            "finding_id": self._finding_id(target, rule_id),
            "title": title,
            "status": status,
            "severity": self._severity(score),
            "score": score,
            "confidence": confidence,
            "target": target,
            "evidence": evidence,
            "risk_factors": [risk_factor],
            "attack_path": None,
            "blast_radius": None,
            "recommendations": [recommendation],
            "limitations": [limitation],
        }

    def _insufficient_evidence(
        self,
        *,
        target: dict[str, str | None],
        evidence: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "finding_id": self._finding_id(target, "unknown"),
            "title": "Workload exposure could not be determined",
            "status": "INSUFFICIENT_EVIDENCE",
            "severity": self._severity(0),
            "score": 0,
            "confidence": "low",
            "target": target,
            "evidence": evidence,
            "risk_factors": [],
            "attack_path": None,
            "blast_radius": None,
            "recommendations": [
                "Collect matching Service and Ingress evidence before assessing "
                "exposure."
            ],
            "limitations": [
                "No matching Service evidence established workload reachability."
            ],
        }

    @staticmethod
    def _finding_id(target: Mapping[str, Any], rule_id: str) -> str:
        return deterministic_exposure_finding_id(
            cluster=str(target["cluster"]),
            namespace=str(target["namespace"]),
            kind=str(target["kind"]),
            workload=str(target["name"]),
            rule_id=rule_id,
        )

    def _severity(self, score: int) -> str:
        matching = [
            (threshold, severity)
            for severity, threshold in self.severity_thresholds.items()
            if score >= threshold
        ]
        if not matching:
            return "info"
        return max(matching, key=lambda item: item[0])[1]


def analyze_exposure(
    evidence: Iterable[Evidence | Mapping[str, Any]],
    *,
    config_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Convenience wrapper for :class:`ExposureRuleEngine`."""

    return ExposureRuleEngine(config_path=config_path).analyze(evidence)


evaluate_exposure = analyze_exposure
