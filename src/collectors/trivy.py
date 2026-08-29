"""Collect vulnerability evidence by scanning explicit container images with Trivy.

Only image values supplied by the workload collector are accepted.  The Trivy
command is fixed here: callers cannot add flags, choose another executable, or
enable a shell.  All input is validated before the first subprocess is started.
"""

from __future__ import annotations

import json
import subprocess
import unicodedata
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any, Callable

from src.models import Evidence, ScanResult, ScanStatus, Target

COLLECTOR_VERSION = "1.0.0"
EVIDENCE_SOURCE = "trivy"
DEFAULT_MAX_IMAGES = 20
TRIVY_TIMEOUT_SECONDS = 300
SUPPORTED_TRIVY_SEVERITIES = (
    "UNKNOWN",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _validate_image(image: Any) -> str:
    """Validate one image argument before it can reach ``subprocess.run``."""

    image = _required_text(image, "image")
    if image != image.strip():
        raise ValueError("image must not begin or end with whitespace")
    if image.startswith("-"):
        raise ValueError("image must not begin with '-'")
    if any(unicodedata.category(character) == "Cc" for character in image):
        raise ValueError("image must not contain control characters")
    return image


def normalize_trivy_severities(
    value: str | Iterable[str] | None,
) -> tuple[str, ...]:
    """Return a validated, de-duplicated Trivy severity allowlist."""

    if value is None:
        return ()
    if isinstance(value, str):
        raw_items = value.split(",")
    elif isinstance(value, (bytes, Mapping)) or not isinstance(value, Iterable):
        raise TypeError(
            "Trivy severities must be a comma-separated string or iterable"
        )
    else:
        raw_items = list(value)

    severities: list[str] = []
    for index, item in enumerate(raw_items):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"Trivy severity at index {index} must not be empty")
        severity = item.strip().upper()
        if severity not in SUPPORTED_TRIVY_SEVERITIES:
            allowed = ", ".join(SUPPORTED_TRIVY_SEVERITIES)
            raise ValueError(
                f"unsupported Trivy severity {item!r}; expected one of: {allowed}"
            )
        if severity not in severities:
            severities.append(severity)
    if not severities:
        raise ValueError("at least one Trivy severity is required")
    return tuple(severities)


def _image_entries(
    image_references: Iterable[str | Mapping[str, Any]],
) -> list[tuple[str, dict[str, str]]]:
    """Normalize workload collector image records and preserve their context."""

    if isinstance(image_references, (str, bytes)) or not isinstance(
        image_references, Iterable
    ):
        raise TypeError("image_references must be an iterable of image records")

    entries: list[tuple[str, dict[str, str]]] = []
    for index, item in enumerate(image_references):
        context: dict[str, str] = {}
        if isinstance(item, str):
            image = item
        elif isinstance(item, Mapping):
            image = item.get("image")
            for key in ("name", "type"):
                value = item.get(key)
                if value is not None:
                    context[key] = _required_text(
                        value, f"image_references[{index}].{key}"
                    )
        else:
            raise TypeError(
                f"image_references[{index}] must be a string or mapping"
            )
        entries.append((_validate_image(image), context))
    return entries


def _deduplicate_images(
    entries: Iterable[tuple[str, dict[str, str]]],
) -> list[tuple[str, list[dict[str, str]]]]:
    contexts_by_image: dict[str, list[dict[str, str]]] = {}
    for image, context in entries:
        contexts = contexts_by_image.setdefault(image, [])
        if context and context not in contexts:
            contexts.append(context)
    return list(contexts_by_image.items())


def _optional_text(value: Any, field_name: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string when present")
    return value


def _image_digest(report: Mapping[str, Any], image_reference: str) -> str | None:
    metadata = report.get("Metadata")
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, Mapping):
        raise ValueError("Trivy report Metadata must be an object")

    repo_digests = metadata.get("RepoDigests", [])
    if repo_digests is None:
        repo_digests = []
    if not isinstance(repo_digests, list) or not all(
        isinstance(item, str) for item in repo_digests
    ):
        raise ValueError("Trivy report Metadata.RepoDigests must be a string list")
    for repo_digest in repo_digests:
        if "@" in repo_digest:
            digest = repo_digest.rsplit("@", 1)[1]
            if digest:
                return digest

    if "@" in image_reference:
        digest = image_reference.rsplit("@", 1)[1]
        if digest:
            return digest

    artifact_id = _optional_text(report.get("ArtifactID"), "Trivy report ArtifactID")
    if artifact_id:
        return artifact_id

    return _optional_text(metadata.get("ImageID"), "Trivy report Metadata.ImageID")


def _trivy_version(report: Mapping[str, Any]) -> str:
    """Read a version embedded by Trivy/report wrappers, or mark it unavailable.

    Trivy's JSON schema has varied over time and some releases do not embed the
    executable version.  We intentionally do not run a second, non-scan command:
    this keeps the process allowlist to exactly one fixed command per image.
    """

    for key in ("TrivyVersion", "trivy_version"):
        value = report.get(key)
        if isinstance(value, str) and value.strip():
            return value

    for key in ("Trivy", "Scanner"):
        scanner = report.get(key)
        if isinstance(scanner, Mapping):
            value = scanner.get("Version")
            if isinstance(value, str) and value.strip():
                return value
    return "unavailable"


def parse_trivy_report(
    report: Mapping[str, Any], *, image_reference: str
) -> dict[str, Any]:
    """Normalize one decoded Trivy image report into stable evidence details."""

    image_reference = _validate_image(image_reference)
    if not isinstance(report, Mapping):
        raise ValueError("Trivy output must be a JSON object")

    raw_results = report.get("Results")
    if raw_results is None:
        schema_version = report.get("SchemaVersion")
        artifact_name = report.get("ArtifactName")
        artifact_type = report.get("ArtifactType")
        if (
            isinstance(schema_version, int)
            and not isinstance(schema_version, bool)
            and schema_version > 0
            and isinstance(artifact_name, str)
            and artifact_name.strip()
            and artifact_type == "container_image"
        ):
            # Trivy omits Results entirely when a successful severity-filtered
            # image scan has no matching vulnerabilities.
            raw_results = []
    if not isinstance(raw_results, list):
        raise ValueError("Trivy report Results must be a list")

    vulnerabilities: list[dict[str, str | None]] = []
    for result_index, raw_result in enumerate(raw_results):
        if not isinstance(raw_result, Mapping):
            raise ValueError(f"Trivy report Results[{result_index}] must be an object")
        raw_vulnerabilities = raw_result.get("Vulnerabilities", [])
        if raw_vulnerabilities is None:
            raw_vulnerabilities = []
        if not isinstance(raw_vulnerabilities, list):
            raise ValueError(
                f"Trivy report Results[{result_index}].Vulnerabilities must be a list"
            )

        for vulnerability_index, raw_vulnerability in enumerate(raw_vulnerabilities):
            prefix = (
                f"Trivy report Results[{result_index}]"
                f".Vulnerabilities[{vulnerability_index}]"
            )
            if not isinstance(raw_vulnerability, Mapping):
                raise ValueError(f"{prefix} must be an object")

            references = raw_vulnerability.get("References", [])
            if references is None:
                references = []
            if not isinstance(references, list) or not all(
                isinstance(item, str) for item in references
            ):
                raise ValueError(f"{prefix}.References must be a string list")
            primary_url = _optional_text(
                raw_vulnerability.get("PrimaryURL"), f"{prefix}.PrimaryURL"
            )

            vulnerabilities.append(
                {
                    "vulnerability_id": _required_text(
                        raw_vulnerability.get("VulnerabilityID"),
                        f"{prefix}.VulnerabilityID",
                    ),
                    "severity": _required_text(
                        raw_vulnerability.get("Severity"), f"{prefix}.Severity"
                    ).upper(),
                    "package_name": _required_text(
                        raw_vulnerability.get("PkgName"), f"{prefix}.PkgName"
                    ),
                    "installed_version": _required_text(
                        raw_vulnerability.get("InstalledVersion"),
                        f"{prefix}.InstalledVersion",
                    ),
                    # An empty Trivy FixedVersion means the vulnerability is
                    # currently unfixed.  It remains in evidence as ``None``.
                    "fixed_version": _optional_text(
                        raw_vulnerability.get("FixedVersion"),
                        f"{prefix}.FixedVersion",
                    ),
                    "title": _optional_text(
                        raw_vulnerability.get("Title"), f"{prefix}.Title"
                    ),
                    "reference": primary_url or (references[0] if references else None),
                }
            )

    return {
        "image_reference": image_reference,
        "image_digest": _image_digest(report, image_reference),
        "trivy_version": _trivy_version(report),
        "vulnerability_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }


class TrivyImageCollector:
    """Scan a bounded set of explicit, validated image references."""

    def __init__(
        self,
        *,
        max_images: int = DEFAULT_MAX_IMAGES,
        severities: str | Iterable[str] | None = None,
        collector_version: str = COLLECTOR_VERSION,
        process_runner: Callable[..., Any] | None = None,
    ) -> None:
        if isinstance(max_images, bool) or not isinstance(max_images, int):
            raise TypeError("max_images must be an integer")
        if max_images < 1:
            raise ValueError("max_images must be at least 1")
        self.max_images = max_images
        self.severities = normalize_trivy_severities(severities)
        self.collector_version = _required_text(
            collector_version, "collector_version"
        )
        if process_runner is not None and not callable(process_runner):
            raise TypeError("process_runner must be callable")
        self._process_runner = process_runner

    def collect(
        self,
        image_references: Iterable[str | Mapping[str, Any]],
        *,
        target: Target | None = None,
        cluster: str = "unknown",
        namespace: str = "unknown",
        kind: str = "Workload",
        name: str = "unknown",
        observed_at: datetime | str | None = None,
    ) -> ScanResult:
        """Run one fixed Trivy command for each unique image.

        Invalid caller input raises before any command is run.  Runtime and
        report failures return ``COLLECTION_FAILED`` and no evidence, preventing
        an incomplete scan from being interpreted as clean.
        """

        entries = _image_entries(image_references)
        unique_images = _deduplicate_images(entries)
        if len(unique_images) > self.max_images:
            raise ValueError(
                f"image count {len(unique_images)} exceeds maximum {self.max_images}"
            )

        if target is None:
            target = Target(
                cluster=_required_text(cluster, "cluster"),
                namespace=_required_text(namespace, "namespace"),
                kind=_required_text(kind, "kind"),
                name=_required_text(name, "name"),
            )
        elif not isinstance(target, Target):
            raise TypeError("target must be a Target")

        timestamp = observed_at or datetime.now(timezone.utc)
        evidence: list[Evidence] = []
        for image, containers in unique_images:
            command = [
                "trivy",
                "image",
                "--quiet",
                "--format",
                "json",
                "--scanners",
                "vuln",
            ]
            if self.severities:
                command.extend(["--severity", ",".join(self.severities)])
            command.append(image)
            try:
                # Resolve the default at call time so existing callers can
                # still patch subprocess.run, while pipeline callers can
                # inject a fully offline process runner.
                runner = self._process_runner or subprocess.run
                completed = runner(
                    command,
                    shell=False,
                    timeout=TRIVY_TIMEOUT_SECONDS,
                    capture_output=True,
                    text=True,
                )
                if completed.returncode != 0:
                    error = completed.stderr.strip() if completed.stderr else "no error output"
                    raise RuntimeError(
                        f"Trivy exited with status {completed.returncode}: {error[:500]}"
                    )
                stdout = completed.stdout
                if isinstance(stdout, bytes):
                    stdout = stdout.decode("utf-8")
                report = json.loads(stdout)
                details = parse_trivy_report(report, image_reference=image)
                details["containers"] = containers
                evidence.append(
                    Evidence(
                        source=EVIDENCE_SOURCE,
                        observed_at=timestamp,
                        collector_version=self.collector_version,
                        details=details,
                    )
                )
            except (
                FileNotFoundError,
                OSError,
                subprocess.TimeoutExpired,
                UnicodeDecodeError,
                json.JSONDecodeError,
                TypeError,
                ValueError,
                RuntimeError,
            ) as exc:
                return ScanResult(
                    target=target,
                    status=ScanStatus.COLLECTION_FAILED,
                    errors=[
                        f"failed to scan image {image!r}: {type(exc).__name__}: {exc}"
                    ],
                )

        return ScanResult(
            target=target,
            status=ScanStatus.COMPLETE,
            evidence=evidence,
        )


def collect_trivy_images(
    image_references: Iterable[str | Mapping[str, Any]],
    *,
    target: Target | None = None,
    cluster: str = "unknown",
    namespace: str = "unknown",
    kind: str = "Workload",
    name: str = "unknown",
    max_images: int = DEFAULT_MAX_IMAGES,
    severities: str | Iterable[str] | None = None,
    observed_at: datetime | str | None = None,
    process_runner: Callable[..., Any] | None = None,
) -> ScanResult:
    """Convenience wrapper for collecting Trivy evidence."""

    return TrivyImageCollector(
        max_images=max_images,
        severities=severities,
        process_runner=process_runner,
    ).collect(
        image_references,
        target=target,
        cluster=cluster,
        namespace=namespace,
        kind=kind,
        name=name,
        observed_at=observed_at,
    )


__all__ = [
    "COLLECTOR_VERSION",
    "DEFAULT_MAX_IMAGES",
    "EVIDENCE_SOURCE",
    "SUPPORTED_TRIVY_SEVERITIES",
    "TRIVY_TIMEOUT_SECONDS",
    "TrivyImageCollector",
    "collect_trivy_images",
    "normalize_trivy_severities",
    "parse_trivy_report",
]
