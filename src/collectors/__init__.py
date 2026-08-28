"""Read-only collectors for Kubernetes security evidence."""

from .security_context import (
    COLLECTOR_VERSION,
    SecurityContextCollector,
    collect_security_context,
)

__all__ = [
    "COLLECTOR_VERSION",
    "SecurityContextCollector",
    "collect_security_context",
]
