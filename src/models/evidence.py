"""Normalized output models shared by all security collectors."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Mapping


def _required_string(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _parse_observed_at(value: datetime | str) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("observed_at must be a valid ISO 8601 timestamp") from exc

    if not isinstance(value, datetime):
        raise TypeError("observed_at must be a datetime or ISO 8601 string")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("observed_at must include a timezone")

    return value.astimezone(timezone.utc)


def _format_observed_at(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class ScanStatus(StrEnum):
    """Supported outcomes for collector execution."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    COLLECTION_FAILED = "COLLECTION_FAILED"


@dataclass(slots=True)
class Target:
    """The Kubernetes resource and optional container being inspected."""

    cluster: str
    namespace: str
    kind: str
    name: str
    container: str | None = None

    def __post_init__(self) -> None:
        _required_string(self.cluster, "cluster")
        _required_string(self.namespace, "namespace")
        _required_string(self.kind, "kind")
        _required_string(self.name, "name")
        if self.container is not None:
            _required_string(self.container, "container")

    def to_dict(self) -> dict[str, str | None]:
        """Return the target in its normalized JSON-compatible shape."""

        return {
            "cluster": self.cluster,
            "namespace": self.namespace,
            "kind": self.kind,
            "name": self.name,
            "container": self.container,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Target:
        """Build a target from normalized collector data."""

        return cls(
            cluster=value["cluster"],
            namespace=value["namespace"],
            kind=value["kind"],
            name=value["name"],
            container=value.get("container"),
        )


@dataclass(slots=True)
class Evidence:
    """A timestamped observation produced by one collector."""

    source: str
    observed_at: datetime | str
    collector_version: str
    details: dict[str, Any]

    def __post_init__(self) -> None:
        _required_string(self.source, "source")
        _required_string(self.collector_version, "collector_version")
        self.observed_at = _parse_observed_at(self.observed_at)

        if not isinstance(self.details, dict):
            raise TypeError("details must be a dictionary")
        if not all(isinstance(key, str) for key in self.details):
            raise TypeError("details keys must be strings")
        try:
            json.dumps(self.details, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("details must contain only JSON-compatible values") from exc

    def to_dict(self) -> dict[str, Any]:
        """Return the evidence in its normalized JSON-compatible shape."""

        return {
            "source": self.source,
            "observed_at": _format_observed_at(self.observed_at),
            "collector_version": self.collector_version,
            "details": self.details.copy(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Evidence:
        """Build evidence from normalized collector data."""

        return cls(
            source=value["source"],
            observed_at=value["observed_at"],
            collector_version=value["collector_version"],
            details=dict(value["details"]),
        )


@dataclass(slots=True)
class ScanResult:
    """The complete normalized response returned by a collector or scan."""

    target: Target
    status: ScanStatus | str
    evidence: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.target, Target):
            raise TypeError("target must be a Target")

        try:
            self.status = ScanStatus(self.status)
        except (TypeError, ValueError) as exc:
            allowed = ", ".join(status.value for status in ScanStatus)
            raise ValueError(f"status must be one of: {allowed}") from exc

        if not isinstance(self.evidence, list) or not all(
            isinstance(item, Evidence) for item in self.evidence
        ):
            raise TypeError("evidence must be a list of Evidence objects")
        if not isinstance(self.errors, list) or not all(
            isinstance(item, str) and item.strip() for item in self.errors
        ):
            raise TypeError("errors must be a list of non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        """Return the complete scan result as JSON-compatible data."""

        return {
            "target": self.target.to_dict(),
            "status": self.status.value,
            "evidence": [item.to_dict() for item in self.evidence],
            "errors": self.errors.copy(),
        }

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize the scan result as JSON."""

        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ScanResult:
        """Build a scan result from normalized collector data."""

        return cls(
            target=Target.from_dict(value["target"]),
            status=value["status"],
            evidence=[Evidence.from_dict(item) for item in value.get("evidence", [])],
            errors=list(value.get("errors", [])),
        )
