"""Normalized model for deterministic Kubernetes attack-path correlation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping


_ATTACK_PATH_ID = re.compile(r"^KAP-[0-9a-f]{12}$")
_FINDING_ID = re.compile(r"^KSA-[0-9a-fA-F]{12}$")


class AttackPathStatus(StrEnum):
    """The only assertion made by deterministic correlation."""

    PLAUSIBLE = "PLAUSIBLE"


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _string_list(
    value: Any, field_name: str, *, minimum: int = 0
) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise TypeError(f"{field_name} must be a list of non-empty strings")
    if len(value) < minimum:
        raise ValueError(f"{field_name} must contain at least {minimum} items")
    if len(value) != len(set(value)):
        raise ValueError(f"{field_name} must not contain duplicates")
    return value.copy()


@dataclass(slots=True)
class AttackPath:
    """A plausible path supported by at least two confirmed risk factors.

    The model deliberately has no field capable of representing successful
    exploitation. Correlation describes risk relationships, not runtime events.
    """

    attack_path_id: str
    status: AttackPathStatus | str
    title: str
    score: int
    severity: str
    supporting_finding_ids: list[str]
    risk_factors: list[str]
    explanation: str
    limitations: list[str]

    def __post_init__(self) -> None:
        if not isinstance(self.attack_path_id, str) or not _ATTACK_PATH_ID.fullmatch(
            self.attack_path_id
        ):
            raise ValueError("attack_path_id must match KAP-<12 lowercase hex>")

        try:
            self.status = AttackPathStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise ValueError("status must be PLAUSIBLE") from exc

        self.title = _required_text(self.title, "title")
        if (
            not isinstance(self.score, int)
            or isinstance(self.score, bool)
            or not 0 <= self.score <= 100
        ):
            raise ValueError("score must be an integer between 0 and 100")
        if self.severity != "high":
            raise ValueError("severity must be high")

        self.supporting_finding_ids = _string_list(
            self.supporting_finding_ids, "supporting_finding_ids", minimum=1
        )
        if not all(
            _FINDING_ID.fullmatch(finding_id)
            for finding_id in self.supporting_finding_ids
        ):
            raise ValueError("supporting_finding_ids must contain valid KSA IDs")
        self.risk_factors = _string_list(
            self.risk_factors, "risk_factors", minimum=2
        )
        self.explanation = _required_text(self.explanation, "explanation")
        self.limitations = _string_list(
            self.limitations, "limitations", minimum=1
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the exact JSON-compatible attack-path shape."""

        return {
            "attack_path_id": self.attack_path_id,
            "status": self.status.value,
            "title": self.title,
            "score": self.score,
            "severity": self.severity,
            "supporting_finding_ids": self.supporting_finding_ids.copy(),
            "risk_factors": self.risk_factors.copy(),
            "explanation": self.explanation,
            "limitations": self.limitations.copy(),
        }

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize with stable key ordering."""

        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            indent=indent,
            separators=None if indent is not None else (",", ":"),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> AttackPath:
        """Build and validate an attack path from normalized data."""

        if not isinstance(value, Mapping):
            raise TypeError("attack path must be a mapping")
        return cls(
            attack_path_id=value["attack_path_id"],
            status=value["status"],
            title=value["title"],
            score=value["score"],
            severity=value["severity"],
            supporting_finding_ids=list(value["supporting_finding_ids"]),
            risk_factors=list(value["risk_factors"]),
            explanation=value["explanation"],
            limitations=list(value["limitations"]),
        )


__all__ = ["AttackPath", "AttackPathStatus"]
