"""Shared data models for normalized collector and analysis output."""

from .attack_path import AttackPath, AttackPathStatus
from .evidence import Evidence, ScanResult, ScanStatus, Target

__all__ = [
    "AttackPath",
    "AttackPathStatus",
    "Evidence",
    "ScanResult",
    "ScanStatus",
    "Target",
]
