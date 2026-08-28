"""Deterministic orchestration for one read-only Kubernetes security scan."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from src.analysis.exposure_rules import analyze_exposure
from src.analysis.network_policy_rules import analyze_network_policy
from src.analysis.rbac_rules import analyze_rbac
from src.analysis.security_context_rules import analyze_security_context
from src.analysis.trivy_rules import analyze_trivy
from src.collectors.exposure import ExposureCollector
from src.collectors.kubernetes_workload import KubernetesWorkloadCollector
from src.collectors.network_policy import NetworkPolicyCollector
from src.collectors.rbac import RBACCollector
from src.collectors.security_context import SecurityContextCollector
from src.collectors.trivy import TrivyImageCollector
from src.models import ScanResult, ScanStatus, Target

DEFAULT_REPORT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas" / "scan-report.schema.json"
)
DEFAULT_FINDING_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas" / "finding.schema.json"
)

SUPPORTED_WORKLOAD_KINDS = frozenset(
    {"Pod", "Deployment", "StatefulSet", "DaemonSet"}
)
SECONDARY_COLLECTORS = (
    "security_context",
    "exposure",
    "network_policy",
    "rbac",
    "trivy",
)
ANALYZERS = SECONDARY_COLLECTORS
SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}


class WorkloadCollectionError(RuntimeError):
    """Raised when primary workload evidence cannot safely start a scan."""

    def __init__(self, message: str, *, result: ScanResult | None = None) -> None:
        super().__init__(message)
        self.result = result


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _target(value: Target | Mapping[str, Any]) -> Target:
    if isinstance(value, Target):
        result = value
    elif isinstance(value, Mapping):
        try:
            result = Target(
                cluster=_required_text(value.get("cluster"), "target.cluster"),
                namespace=_required_text(
                    value.get("namespace"), "target.namespace"
                ),
                kind=_required_text(value.get("kind"), "target.kind"),
                name=_required_text(value.get("name"), "target.name"),
                container=value.get("container"),
            )
        except AttributeError as exc:  # defensive for unusual Mapping objects
            raise TypeError("target must be a Target or mapping") from exc
    else:
        raise TypeError("target must be a Target or mapping")

    if result.container is not None:
        raise ValueError("target.container must be null for a workload scan")
    if result.kind not in SUPPORTED_WORKLOAD_KINDS:
        supported = ", ".join(sorted(SUPPORTED_WORKLOAD_KINDS))
        raise ValueError(
            f"unsupported workload kind {result.kind!r}; expected one of: {supported}"
        )
    return result


def _load_schema(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as source:
            schema = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read scan report schema: {path}") from exc
    if not isinstance(schema, dict):
        raise ValueError("scan report schema must be an object")
    Draft202012Validator.check_schema(schema)
    return schema


def _invoke_analyzer(analyzer: Any, evidence: Any) -> Any:
    if hasattr(analyzer, "analyze") and callable(analyzer.analyze):
        return analyzer.analyze(evidence)
    if callable(analyzer):
        return analyzer(evidence)
    raise TypeError("analyzer must be callable or expose analyze()")


def _workload_inputs(
    details: Mapping[str, Any], *, kind: str
) -> tuple[dict[str, Any], dict[str, str], list[Any]]:
    """Extract and validate the shared inputs used by secondary collectors."""

    workload = details["manifest"]
    pod_spec = details["pod_spec"]
    images = details["container_images"]
    if not isinstance(workload, Mapping):
        raise TypeError("workload manifest is not an object")
    if not isinstance(pod_spec, Mapping):
        raise TypeError("pod spec is not an object")
    if not isinstance(images, list) or not images:
        raise ValueError("workload has no container images")

    metadata = workload.get("metadata")
    if not isinstance(metadata, Mapping):
        raise TypeError("workload metadata is not an object")
    if kind == "Pod":
        pod_metadata = metadata
    else:
        spec = workload.get("spec")
        if not isinstance(spec, Mapping):
            raise TypeError("workload spec is not an object")
        template = spec.get("template")
        if not isinstance(template, Mapping):
            raise TypeError("workload pod template is not an object")
        pod_metadata = template.get("metadata", {})
        if not isinstance(pod_metadata, Mapping):
            raise TypeError("workload pod template metadata is not an object")

    raw_labels = pod_metadata.get("labels", {})
    if raw_labels is None:
        raw_labels = {}
    if not isinstance(raw_labels, Mapping) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in raw_labels.items()
    ):
        raise TypeError("workload pod labels must be a string mapping")

    service_account = pod_spec.get(
        "serviceAccountName", pod_spec.get("service_account_name", "default")
    )
    _required_text(service_account or "default", "service account")
    return dict(workload), dict(raw_labels), images.copy()


class DeterministicScanPipeline:
    """Collect evidence, apply deterministic rules, and return one report.

    Kubernetes clients and the Trivy process runner are supplied by the caller.
    No kubeconfig is loaded and no subprocess is required by tests.
    """

    def __init__(
        self,
        kubernetes_client: Any,
        *,
        approved_namespace: str,
        apps_client: Any | None = None,
        networking_client: Any | None = None,
        rbac_client: Any | None = None,
        trivy_process_runner: Callable[..., Any] | None = None,
        analyzers: Mapping[str, Any] | None = None,
        report_schema_path: str | Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if kubernetes_client is None:
            raise ValueError("kubernetes_client is required")
        self.approved_namespace = _required_text(
            approved_namespace, "approved_namespace"
        )
        networking_client = networking_client or kubernetes_client
        rbac_client = rbac_client or kubernetes_client

        self.workload_collector = KubernetesWorkloadCollector(
            kubernetes_client,
            approved_namespace=self.approved_namespace,
            apps_client=apps_client,
        )
        self.security_context_collector = SecurityContextCollector()
        self.exposure_collector = ExposureCollector(
            kubernetes_client,
            approved_namespace=self.approved_namespace,
            networking_client=networking_client,
        )
        self.network_policy_collector = NetworkPolicyCollector(
            networking_client,
            approved_namespace=self.approved_namespace,
        )
        self.rbac_collector = RBACCollector(
            rbac_client, approved_namespace=self.approved_namespace
        )
        self.trivy_collector = TrivyImageCollector(
            process_runner=trivy_process_runner
        )

        defaults: dict[str, Any] = {
            "security_context": analyze_security_context,
            "exposure": analyze_exposure,
            "network_policy": analyze_network_policy,
            "rbac": analyze_rbac,
            "trivy": analyze_trivy,
        }
        if analyzers is not None:
            unknown = sorted(set(analyzers).difference(ANALYZERS))
            if unknown:
                raise ValueError("unknown analyzers: " + ", ".join(unknown))
            defaults.update(analyzers)
        self.analyzers = defaults

        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if not callable(self._clock):
            raise TypeError("clock must be callable")
        schema = _load_schema(Path(report_schema_path or DEFAULT_REPORT_SCHEMA_PATH))
        checker = FormatChecker()
        self._validator = Draft202012Validator(schema, format_checker=checker)
        self._finding_validator = Draft202012Validator(
            _load_schema(DEFAULT_FINDING_SCHEMA_PATH), format_checker=checker
        )

    def run(
        self,
        target: Target | Mapping[str, Any],
        *,
        observed_at: datetime | str | None = None,
    ) -> dict[str, Any]:
        """Run one scan. Primary collection failure raises and stops execution."""

        scan_target = _target(target)
        if scan_target.namespace != self.approved_namespace:
            raise PermissionError(
                f"namespace {scan_target.namespace!r} is not the approved namespace "
                f"{self.approved_namespace!r}"
            )
        timestamp: datetime | str = (
            observed_at if observed_at is not None else self._clock()
        )

        workload_result = self.workload_collector.collect(
            namespace=scan_target.namespace,
            kind=scan_target.kind,
            name=scan_target.name,
            cluster=scan_target.cluster,
            observed_at=timestamp,
        )
        if workload_result.status is not ScanStatus.COMPLETE:
            reason = "; ".join(workload_result.errors) or "workload collection failed"
            raise WorkloadCollectionError(reason, result=workload_result)

        try:
            details = workload_result.evidence[0].details
            workload, pod_labels, images = _workload_inputs(
                details, kind=scan_target.kind
            )
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise WorkloadCollectionError(
                f"workload evidence could not be extracted: {exc}",
                result=workload_result,
            ) from exc

        collector_results = self._collect_secondary(
            workload=workload,
            pod_labels=pod_labels,
            images=images,
            target=scan_target,
            observed_at=timestamp,
        )

        collector_status = {"workload": ScanStatus.COMPLETE.value}
        evidence_gaps: list[dict[str, Any]] = []
        for name in SECONDARY_COLLECTORS:
            result = collector_results[name]
            collector_status[name] = result.status.value
            if result.status is not ScanStatus.COMPLETE:
                evidence_gaps.append(
                    self._gap(
                        component=name,
                        stage="COLLECTION",
                        status=result.status.value,
                        errors=result.errors,
                    )
                )

        analyzer_inputs: dict[str, Any] = {
            "security_context": collector_results["security_context"].evidence,
            "exposure": collector_results["exposure"].evidence,
            "network_policy": collector_results["network_policy"],
            "rbac": collector_results["rbac"],
            "trivy": collector_results["trivy"],
        }
        analyzer_status: dict[str, str] = {}
        findings: list[dict[str, Any]] = []
        for name in ANALYZERS:
            try:
                produced = _invoke_analyzer(
                    self.analyzers[name], analyzer_inputs[name]
                )
                if not isinstance(produced, list):
                    raise TypeError("analyzer output must be a list")
                normalized: list[dict[str, Any]] = []
                for finding in produced:
                    if not isinstance(finding, Mapping):
                        raise TypeError("each analyzer result must be an object")
                    item = deepcopy(dict(finding))
                    self._finding_validator.validate(item)
                    normalized.append(item)
                findings.extend(normalized)
                analyzer_status[name] = "COMPLETE"
            except Exception as exc:
                analyzer_status[name] = "ANALYSIS_FAILED"
                evidence_gaps.append(
                    self._gap(
                        component=name,
                        stage="ANALYSIS",
                        status="ANALYSIS_FAILED",
                        errors=[f"{type(exc).__name__}: {exc}"],
                    )
                )

        findings.sort(key=self._finding_sort_key)
        evidence_gaps.sort(
            key=lambda gap: (gap["stage"], gap["component"], gap["status"])
        )
        scan_status = "PARTIAL" if evidence_gaps else "COMPLETE"
        summary = {severity: 0 for severity in SEVERITIES}
        for finding in findings:
            summary[finding["severity"]] += 1

        report = {
            "scan_status": scan_status,
            "target": scan_target.to_dict(),
            "collector_status": collector_status,
            "analyzer_status": analyzer_status,
            "findings": findings,
            "evidence_gaps": evidence_gaps,
            "summary": summary,
        }
        self._validator.validate(report)
        return report

    scan = run

    def run_json(
        self,
        target: Target | Mapping[str, Any],
        *,
        observed_at: datetime | str | None = None,
        indent: int | None = None,
    ) -> str:
        """Run one scan and serialize the report with stable key ordering."""

        return json.dumps(
            self.run(target, observed_at=observed_at),
            ensure_ascii=False,
            sort_keys=True,
            indent=indent,
            separators=None if indent is not None else (",", ":"),
        )

    def _collect_secondary(
        self,
        *,
        workload: dict[str, Any],
        pod_labels: dict[str, str],
        images: list[Any],
        target: Target,
        observed_at: datetime | str,
    ) -> dict[str, ScanResult]:
        calls: dict[str, Callable[[], ScanResult]] = {
            "security_context": lambda: ScanResult(
                target=target,
                status=ScanStatus.COMPLETE,
                evidence=self.security_context_collector.collect(
                    workload,
                    cluster=target.cluster,
                    observed_at=observed_at,
                ),
            ),
            "exposure": lambda: self.exposure_collector.collect(
                namespace=target.namespace,
                kind=target.kind,
                name=target.name,
                pod_labels=pod_labels,
                cluster=target.cluster,
                observed_at=observed_at,
            ),
            "network_policy": lambda: self.network_policy_collector.collect(
                namespace=target.namespace,
                kind=target.kind,
                name=target.name,
                pod_labels=pod_labels,
                cluster=target.cluster,
                observed_at=observed_at,
            ),
            "rbac": lambda: self.rbac_collector.collect(
                workload, cluster=target.cluster, observed_at=observed_at
            ),
            "trivy": lambda: self.trivy_collector.collect(
                images, target=target, observed_at=observed_at
            ),
        }
        results: dict[str, ScanResult] = {}
        for name in SECONDARY_COLLECTORS:
            try:
                result = calls[name]()
                if not isinstance(result, ScanResult):
                    raise TypeError("collector output must be a ScanResult")
                results[name] = result
            except Exception as exc:
                results[name] = ScanResult(
                    target=target,
                    status=ScanStatus.COLLECTION_FAILED,
                    errors=[f"{type(exc).__name__}: {exc}"],
                )
        return results

    @staticmethod
    def _gap(
        *, component: str, stage: str, status: str, errors: list[str]
    ) -> dict[str, Any]:
        return {
            "component": component,
            "stage": stage,
            "status": status,
            "errors": errors.copy() or [f"{component} did not provide complete evidence"],
        }

    @staticmethod
    def _finding_sort_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
        target = finding["target"]
        return (
            _SEVERITY_RANK[finding["severity"]],
            target["cluster"],
            target["namespace"],
            target["kind"],
            target["name"],
            target.get("container") or "",
            finding["finding_id"],
        )


# Short name for application code and a functional convenience entry point.
ScanPipeline = DeterministicScanPipeline


def run_scan(
    target: Target | Mapping[str, Any],
    *,
    kubernetes_client: Any,
    approved_namespace: str,
    apps_client: Any | None = None,
    networking_client: Any | None = None,
    rbac_client: Any | None = None,
    trivy_process_runner: Callable[..., Any] | None = None,
    observed_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Construct a pipeline from injected dependencies and run one scan."""

    return DeterministicScanPipeline(
        kubernetes_client,
        approved_namespace=approved_namespace,
        apps_client=apps_client,
        networking_client=networking_client,
        rbac_client=rbac_client,
        trivy_process_runner=trivy_process_runner,
    ).run(target, observed_at=observed_at)


__all__ = [
    "DEFAULT_REPORT_SCHEMA_PATH",
    "DEFAULT_FINDING_SCHEMA_PATH",
    "DeterministicScanPipeline",
    "ScanPipeline",
    "WorkloadCollectionError",
    "run_scan",
]
