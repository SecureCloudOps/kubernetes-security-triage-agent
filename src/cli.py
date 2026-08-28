"""Command-line entry point for Kubernetes security scans."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from src.pipeline import DEFAULT_REPORT_SCHEMA_PATH, DeterministicScanPipeline
from src.reporting.markdown import redact_report, render_markdown

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2
EXIT_PARTIAL = 3
EXIT_AI_FAILED = 4

FAIL_LEVELS = ("critical", "high", "medium", "low", "none")
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_CORE_METHODS = frozenset({"read_namespaced_pod", "list_namespaced_service"})
_APPS_METHODS = frozenset(
    {
        "read_namespaced_deployment",
        "read_namespaced_stateful_set",
        "read_namespaced_daemon_set",
    }
)
_NETWORKING_METHODS = frozenset(
    {"list_namespaced_ingress", "list_namespaced_network_policy"}
)
_RBAC_METHODS = frozenset(
    {
        "list_namespaced_role_binding",
        "list_cluster_role_binding",
        "read_namespaced_role",
        "read_cluster_role",
    }
)


class CliError(RuntimeError):
    """A safe error whose message may be displayed to the operator."""


class ReadOnlyApiClient:
    """Expose only the Kubernetes read methods required by the collectors."""

    __slots__ = ("__api", "__allowed_methods")

    def __init__(self, api: Any, allowed_methods: frozenset[str]) -> None:
        object.__setattr__(self, "_ReadOnlyApiClient__api", api)
        object.__setattr__(self, "_ReadOnlyApiClient__allowed_methods", allowed_methods)

    def __getattr__(self, name: str) -> Any:
        if name not in self.__allowed_methods:
            raise AttributeError(f"Kubernetes method {name!r} is not permitted")
        method = getattr(self.__api, name)
        if not callable(method):
            raise AttributeError(f"Kubernetes method {name!r} is unavailable")
        return method


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CliError(f"{field_name} is required")
    return value.strip()


def _kubernetes_modules() -> tuple[Any, Any]:
    try:
        from kubernetes import client, config
    except ImportError as exc:
        raise CliError(
            "the Kubernetes Python client is not installed; install the project dependencies"
        ) from exc
    return client, config


def load_current_context() -> tuple[str, dict[str, ReadOnlyApiClient]]:
    """Load the active kubeconfig context and construct allowlisted API clients."""

    client, config = _kubernetes_modules()
    try:
        _contexts, current = config.list_kube_config_contexts()
        if not isinstance(current, dict):
            raise CliError("no current Kubernetes context is configured")
        context_name = _required_text(current.get("name"), "current context name")
        context_details = current.get("context")
        if not isinstance(context_details, dict):
            raise CliError("the current Kubernetes context is invalid")
        cluster = _required_text(
            context_details.get("cluster"), "current context cluster"
        )
        config.load_kube_config(context=context_name)
        clients = {
            "core": ReadOnlyApiClient(client.CoreV1Api(), _CORE_METHODS),
            "apps": ReadOnlyApiClient(client.AppsV1Api(), _APPS_METHODS),
            "networking": ReadOnlyApiClient(
                client.NetworkingV1Api(), _NETWORKING_METHODS
            ),
            "rbac": ReadOnlyApiClient(
                client.RbacAuthorizationV1Api(), _RBAC_METHODS
            ),
        }
    except CliError:
        raise
    except Exception as exc:
        # Kubeconfig and authentication exceptions can contain sensitive data.
        raise CliError(
            f"unable to load the current Kubernetes context ({type(exc).__name__})"
        ) from exc
    return cluster, clients


def _load_report_validator() -> Draft202012Validator:
    try:
        schema = json.loads(DEFAULT_REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError("unable to load the scan report schema") from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _write_reports(output_dir: Path, report: dict[str, Any]) -> tuple[Path, Path]:
    """Validate and render before writing either report file."""

    safe_report = redact_report(report)
    validator = _load_report_validator()
    errors = sorted(
        validator.iter_errors(safe_report),
        key=lambda error: tuple(str(part) for part in error.path),
    )
    if errors:
        raise CliError("the pipeline produced an invalid scan report")

    json_text = json.dumps(
        safe_report,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    markdown_text = render_markdown(safe_report)

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "scan-report.json"
        markdown_path = output_dir / "scan-report.md"
        json_path.write_text(json_text, encoding="utf-8")
        markdown_path.write_text(markdown_text, encoding="utf-8")
    except OSError as exc:
        raise CliError(f"unable to write reports ({type(exc).__name__})") from exc
    return json_path, markdown_path


def _threshold_reached(report: dict[str, Any], threshold: str) -> bool:
    if threshold == "none":
        return False
    minimum_rank = _SEVERITY_RANK[threshold]
    return any(
        isinstance(finding, dict)
        and finding.get("status") == "CONFIRMED"
        and _SEVERITY_RANK.get(str(finding.get("severity")), -1) >= minimum_rank
        for finding in report.get("findings", [])
    )


def _scan(args: argparse.Namespace) -> int:
    namespace = _required_text(args.namespace, "namespace")
    kind = _required_text(args.kind, "kind")
    name = _required_text(args.name, "workload name")
    allowed_namespace = _required_text(
        args.allowed_namespace, "allowed namespace"
    )
    if namespace != allowed_namespace:
        raise CliError(
            "target namespace must match the explicitly allowed namespace"
        )

    cluster, clients = load_current_context()
    pipeline = DeterministicScanPipeline(
        clients["core"],
        approved_namespace=allowed_namespace,
        apps_client=clients["apps"],
        networking_client=clients["networking"],
        rbac_client=clients["rbac"],
    )
    report = pipeline.run(
        {
            "cluster": cluster,
            "namespace": namespace,
            "kind": kind,
            "name": name,
        },
        ai_enabled=args.ai,
    )
    json_path, markdown_path = _write_reports(Path(args.output_dir), report)
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")

    if report.get("ai_status") == "FAILED":
        print(
            "AI analysis failed; deterministic results were preserved.",
            file=sys.stderr,
        )
        return EXIT_AI_FAILED
    if report.get("scan_status") == "PARTIAL":
        print("Scan status is PARTIAL.", file=sys.stderr)
        return EXIT_PARTIAL
    if _threshold_reached(report, args.fail_on):
        print(
            f"Confirmed finding met the --fail-on {args.fail_on} threshold.",
            file=sys.stderr,
        )
        return EXIT_THRESHOLD
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.cli",
        description=(
            "Run a read-only Kubernetes workload scan with deterministic "
            "findings and optional AI interpretation."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan one approved workload")
    scan.add_argument("--namespace", required=True)
    scan.add_argument(
        "--kind",
        required=True,
        choices=("Pod", "Deployment", "StatefulSet", "DaemonSet"),
    )
    scan.add_argument("--name", required=True, help="workload name")
    scan.add_argument("--allowed-namespace", required=True)
    scan.add_argument("--output-dir", default="reports", type=Path)
    scan.add_argument("--fail-on", choices=FAIL_LEVELS, default="none")
    scan.add_argument(
        "--ai",
        action="store_true",
        help="request non-authoritative AI interpretation of deterministic results",
    )
    scan.set_defaults(handler=_scan)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        # Unexpected Kubernetes/process exceptions are intentionally summarized.
        print(
            f"error: scan failed ({type(exc).__name__}); no new report was written",
            file=sys.stderr,
        )
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EXIT_AI_FAILED",
    "EXIT_ERROR",
    "EXIT_OK",
    "EXIT_PARTIAL",
    "EXIT_THRESHOLD",
    "ReadOnlyApiClient",
    "build_parser",
    "load_current_context",
    "main",
]
