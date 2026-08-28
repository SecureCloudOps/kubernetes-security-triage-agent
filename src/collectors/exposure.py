"""Collect evidence describing how a Kubernetes workload may be reached.

The collector accepts an already-loaded workload (or explicit pod labels) and
only lists Services and Ingresses in the workload's approved namespace.  It
does not perform discovery, read resources in other namespaces, or mutate the
cluster.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum, StrEnum
from ipaddress import ip_address
from typing import Any, Mapping

from src.models import Evidence, ScanResult, ScanStatus, Target

COLLECTOR_VERSION = "1.0.0"
EVIDENCE_SOURCE = "kubernetes.exposure"


class ExposureClassification(StrEnum):
    """The strongest network-exposure conclusion supported by the evidence."""

    INTERNAL = "internal"
    POTENTIALLY_EXTERNAL = "potentially_external"
    CONFIRMED_EXTERNAL = "confirmed_external"
    UNKNOWN = "unknown"


_CLASSIFICATION_RANK = {
    ExposureClassification.UNKNOWN: 0,
    ExposureClassification.INTERNAL: 1,
    ExposureClassification.POTENTIALLY_EXTERNAL: 2,
    ExposureClassification.CONFIRMED_EXTERNAL: 3,
}

_INTERNAL_ANNOTATION_KEYS = {
    "service.beta.kubernetes.io/azure-load-balancer-internal",
    "service.beta.kubernetes.io/aws-load-balancer-internal",
    "service.kubernetes.io/ibm-load-balancer-cloud-provider-ip-type",
}

_TYPE_ANNOTATION_KEYS = {
    "cloud.google.com/load-balancer-type",
    "networking.gke.io/load-balancer-type",
    "service.beta.kubernetes.io/aws-load-balancer-scheme",
    "alb.ingress.kubernetes.io/scheme",
    "oci.oraclecloud.com/load-balancer-type",
}


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _plain(value: Any) -> Any:
    """Convert Kubernetes client models into JSON-compatible values."""

    if hasattr(value, "to_dict") and callable(value.to_dict):
        value = value.to_dict()
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, Enum):
        return _plain(value.value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError(f"unsupported Kubernetes response value: {type(value).__name__}")


def _mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    value = _plain(value)
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be an object")
    return value


def _field(value: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    """Read either manifest-style camelCase or client ``to_dict`` keys."""

    for name in names:
        if name in value:
            return value[name]
    return default


def _items(response: Any, field_name: str) -> list[Mapping[str, Any]]:
    response = _mapping(response, field_name)
    raw_items = response.get("items")
    if not isinstance(raw_items, list):
        raise ValueError(f"{field_name}.items must be a list")
    return [
        _mapping(item, f"{field_name}.items[{index}]")
        for index, item in enumerate(raw_items)
    ]


def _optional_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    return _mapping(value, field_name)


def _string_mapping(value: Any, field_name: str) -> dict[str, str]:
    if value is None:
        return {}
    value = _mapping(value, field_name)
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(item, str):
            raise ValueError(f"{field_name}.{key} must be a string")
        result[str(key)] = item
    return result


def _string_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError(f"{field_name} must be a list of strings")
    return list(value)


def _pod_labels(workload: Mapping[str, Any]) -> dict[str, str]:
    kind = _required_text(workload.get("kind"), "workload.kind")
    metadata = _mapping(workload.get("metadata"), "workload.metadata")
    if kind == "Pod":
        pod_metadata = metadata
    elif kind == "CronJob":
        spec = _mapping(workload.get("spec"), "workload.spec")
        job_template = _mapping(
            _field(spec, "jobTemplate", "job_template"),
            "workload.spec.jobTemplate",
        )
        job_spec = _mapping(job_template.get("spec"), "jobTemplate.spec")
        template = _mapping(job_spec.get("template"), "jobTemplate.spec.template")
        pod_metadata = _mapping(template.get("metadata"), "podTemplate.metadata")
    else:
        spec = _mapping(workload.get("spec"), "workload.spec")
        template = _mapping(spec.get("template"), "workload.spec.template")
        pod_metadata = _mapping(template.get("metadata"), "podTemplate.metadata")
    return _string_mapping(pod_metadata.get("labels"), "pod labels")


def _resource_identity(
    resource: Mapping[str, Any], *, namespace: str, resource_type: str
) -> tuple[str, dict[str, str]]:
    metadata = _mapping(resource.get("metadata"), f"{resource_type}.metadata")
    name = _required_text(metadata.get("name"), f"{resource_type}.metadata.name")
    actual_namespace = metadata.get("namespace")
    if actual_namespace is not None and actual_namespace != namespace:
        raise ValueError(
            f"{resource_type} {name!r} belongs to namespace "
            f"{actual_namespace!r}, not requested namespace {namespace!r}"
        )
    annotations = _string_mapping(
        metadata.get("annotations"), f"{resource_type}.metadata.annotations"
    )
    return name, annotations


def _selector_matches(selector: Mapping[str, str], labels: Mapping[str, str]) -> bool:
    return bool(selector) and all(
        labels.get(key) == value for key, value in selector.items()
    )


def _load_balancer_ingress(status: Any, field_name: str) -> list[dict[str, str]]:
    status = _optional_mapping(status, field_name)
    load_balancer = _optional_mapping(
        _field(status, "loadBalancer", "load_balancer"),
        f"{field_name}.loadBalancer",
    )
    raw_ingress = load_balancer.get("ingress", [])
    if raw_ingress is None:
        raw_ingress = []
    if not isinstance(raw_ingress, list):
        raise ValueError(f"{field_name}.loadBalancer.ingress must be a list")

    endpoints: list[dict[str, str]] = []
    for index, raw_endpoint in enumerate(raw_ingress):
        endpoint = _mapping(
            raw_endpoint, f"{field_name}.loadBalancer.ingress[{index}]"
        )
        normalized = {
            key: value
            for key in ("ip", "hostname")
            if isinstance((value := endpoint.get(key)), str) and value.strip()
        }
        if normalized:
            endpoints.append(normalized)
    return endpoints


def _internal_hint(annotations: Mapping[str, str], class_name: str | None) -> bool:
    if class_name and any(
        token in class_name.lower() for token in ("internal", "private")
    ):
        return True

    lowered = {
        key.lower(): value.strip().lower() for key, value in annotations.items()
    }
    for key in _INTERNAL_ANNOTATION_KEYS:
        value = lowered.get(key)
        if value in {"true", "yes", "1", "private", "0.0.0.0/0"}:
            return True
    for key in _TYPE_ANNOTATION_KEYS:
        value = lowered.get(key)
        if value is not None and ("internal" in value or "private" in value):
            return True
    return False


def _is_public_ip(value: str) -> bool:
    try:
        return ip_address(value).is_global
    except ValueError:
        return False


def _endpoints_classification(
    endpoints: list[dict[str, str]], *, internal_hint: bool
) -> ExposureClassification | None:
    if not endpoints:
        return None
    if internal_hint:
        return ExposureClassification.INTERNAL
    if any(
        _is_public_ip(endpoint["ip"])
        for endpoint in endpoints
        if "ip" in endpoint
    ):
        return ExposureClassification.CONFIRMED_EXTERNAL
    if any(
        "hostname" in endpoint
        and not endpoint["hostname"].lower().startswith("internal-")
        and not endpoint["hostname"].lower().endswith((".internal", ".local"))
        for endpoint in endpoints
    ):
        return ExposureClassification.CONFIRMED_EXTERNAL
    return ExposureClassification.POTENTIALLY_EXTERNAL


def _strongest(
    current: ExposureClassification, candidate: ExposureClassification
) -> ExposureClassification:
    if _CLASSIFICATION_RANK[candidate] > _CLASSIFICATION_RANK[current]:
        return candidate
    return current


def _service_evidence(
    service: Mapping[str, Any], *, namespace: str, pod_labels: Mapping[str, str]
) -> tuple[dict[str, Any], ExposureClassification] | None:
    name, annotations = _resource_identity(
        service, namespace=namespace, resource_type="Service"
    )
    spec = _mapping(service.get("spec"), f"Service {name}.spec")
    selector = _string_mapping(spec.get("selector"), f"Service {name}.spec.selector")
    if not _selector_matches(selector, pod_labels):
        return None

    service_type = _field(spec, "type", default="ClusterIP")
    service_type = _required_text(service_type, f"Service {name}.spec.type")
    external_ips = _string_list(
        _field(spec, "externalIPs", "external_i_ps", default=[]),
        f"Service {name}.spec.externalIPs",
    )
    load_balancer_ip = _field(spec, "loadBalancerIP", "load_balancer_ip")
    if load_balancer_ip is not None:
        load_balancer_ip = _required_text(
            load_balancer_ip, f"Service {name}.spec.loadBalancerIP"
        )
    endpoints = _load_balancer_ingress(
        service.get("status"), f"Service {name}.status"
    )
    internal_hint = _internal_hint(annotations, None)

    classification = ExposureClassification.INTERNAL
    reasons: list[str] = []
    if service_type == "NodePort":
        classification = ExposureClassification.POTENTIALLY_EXTERNAL
        reasons.append("NodePort can be reached through an address on a cluster node")
    elif service_type == "LoadBalancer":
        endpoint_classification = _endpoints_classification(
            endpoints, internal_hint=internal_hint
        )
        if endpoint_classification is None:
            classification = ExposureClassification.POTENTIALLY_EXTERNAL
            reasons.append("LoadBalancer is configured but has no assigned endpoint")
        else:
            classification = endpoint_classification
            reasons.append("LoadBalancer has assigned ingress endpoint evidence")

    all_explicit_ips = external_ips + ([load_balancer_ip] if load_balancer_ip else [])
    if all_explicit_ips:
        explicit_classification = (
            ExposureClassification.CONFIRMED_EXTERNAL
            if any(_is_public_ip(value) for value in all_explicit_ips)
            else ExposureClassification.POTENTIALLY_EXTERNAL
        )
        classification = _strongest(classification, explicit_classification)
        reasons.append("Service declares external IP routing")
    if internal_hint and classification is ExposureClassification.INTERNAL:
        reasons.append("Service annotations identify an internal load balancer")
    if not reasons:
        reasons.append(
            "Service is only addressable through a cluster-internal virtual IP"
        )

    return (
        {
            "name": name,
            "type": service_type,
            "selector": selector,
            "clusterIP": _field(spec, "clusterIP", "cluster_ip"),
            "externalIPs": external_ips,
            "loadBalancerIP": load_balancer_ip,
            "loadBalancerIngress": endpoints,
            "annotations": annotations,
            "classification": classification.value,
            "reasons": reasons,
        },
        classification,
    )


def _backend_service_name(backend: Any, field_name: str) -> str | None:
    backend = _optional_mapping(backend, field_name)
    service = _optional_mapping(backend.get("service"), f"{field_name}.service")
    name = service.get("name")
    if name is None:
        # Extensions/v1beta1 used serviceName directly. Supporting it is safe
        # and keeps fixture/older-cluster evidence readable.
        name = _field(backend, "serviceName", "service_name")
    if name is None:
        return None
    return _required_text(name, f"{field_name}.service.name")


def _ingress_backends(ingress_spec: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
    default_backend = _field(ingress_spec, "defaultBackend", "default_backend")
    if (
        name := _backend_service_name(
            default_backend, "Ingress.spec.defaultBackend"
        )
    ):
        names.add(name)

    rules = ingress_spec.get("rules", [])
    if rules is None:
        rules = []
    if not isinstance(rules, list):
        raise ValueError("Ingress.spec.rules must be a list")
    for rule_index, raw_rule in enumerate(rules):
        rule = _mapping(raw_rule, f"Ingress.spec.rules[{rule_index}]")
        http = _optional_mapping(
            rule.get("http"), f"Ingress.spec.rules[{rule_index}].http"
        )
        paths = http.get("paths", [])
        if paths is None:
            paths = []
        if not isinstance(paths, list):
            raise ValueError(
                f"Ingress.spec.rules[{rule_index}].http.paths must be a list"
            )
        for path_index, raw_path in enumerate(paths):
            path = _mapping(
                raw_path,
                f"Ingress.spec.rules[{rule_index}].http.paths[{path_index}]",
            )
            name = _backend_service_name(
                path.get("backend"),
                f"Ingress.spec.rules[{rule_index}].http.paths[{path_index}].backend",
            )
            if name:
                names.add(name)
    return names


def _ingress_evidence(
    ingress: Mapping[str, Any], *, namespace: str, matched_service_names: set[str]
) -> tuple[dict[str, Any], ExposureClassification] | None:
    name, annotations = _resource_identity(
        ingress, namespace=namespace, resource_type="Ingress"
    )
    spec = _mapping(ingress.get("spec"), f"Ingress {name}.spec")
    backend_names = _ingress_backends(spec)
    referenced_services = sorted(backend_names & matched_service_names)
    if not referenced_services:
        return None

    raw_rules = spec.get("rules", []) or []
    hosts = sorted(
        {
            host
            for raw_rule in raw_rules
            if isinstance(raw_rule, Mapping)
            and isinstance((host := raw_rule.get("host")), str)
            and host.strip()
        }
    )
    raw_tls = spec.get("tls", []) or []
    if not isinstance(raw_tls, list):
        raise ValueError(f"Ingress {name}.spec.tls must be a list")
    tls: list[dict[str, Any]] = []
    for index, raw_entry in enumerate(raw_tls):
        entry = _mapping(raw_entry, f"Ingress {name}.spec.tls[{index}]")
        tls.append(
            {
                "hosts": _string_list(
                    entry.get("hosts", []),
                    f"Ingress {name}.spec.tls[{index}].hosts",
                ),
                "secretName": _field(entry, "secretName", "secret_name"),
            }
        )

    class_name = _field(spec, "ingressClassName", "ingress_class_name")
    if class_name is None:
        class_name = annotations.get("kubernetes.io/ingress.class")
    if class_name is not None:
        class_name = _required_text(
            class_name, f"Ingress {name}.spec.ingressClassName"
        )
    endpoints = _load_balancer_ingress(
        ingress.get("status"), f"Ingress {name}.status"
    )
    internal_hint = _internal_hint(annotations, class_name)
    classification = _endpoints_classification(endpoints, internal_hint=internal_hint)
    reasons: list[str]
    if classification is None:
        classification = ExposureClassification.POTENTIALLY_EXTERNAL
        reasons = ["Ingress routes to the Service but has no assigned endpoint"]
    elif classification is ExposureClassification.INTERNAL:
        reasons = ["Ingress endpoint is identified as internal by class or annotations"]
    elif classification is ExposureClassification.CONFIRMED_EXTERNAL:
        reasons = ["Ingress has an assigned public-facing endpoint"]
    else:
        reasons = [
            "Ingress has an assigned endpoint whose public reachability is unclear"
        ]

    return (
        {
            "name": name,
            "services": referenced_services,
            "hosts": hosts,
            "tls": tls,
            "class": class_name,
            "annotations": annotations,
            "loadBalancerIngress": endpoints,
            "classification": classification.value,
            "reasons": reasons,
        },
        classification,
    )


class ExposureCollector:
    """Collect namespace-scoped Service and Ingress exposure evidence."""

    def __init__(
        self,
        client: Any,
        *,
        approved_namespace: str,
        networking_client: Any | None = None,
        collector_version: str = COLLECTOR_VERSION,
    ) -> None:
        if client is None:
            raise ValueError("client is required")
        self._service_client = client
        self._ingress_client = (
            networking_client if networking_client is not None else client
        )
        self.approved_namespace = _required_text(
            approved_namespace, "approved_namespace"
        )
        self.collector_version = _required_text(
            collector_version, "collector_version"
        )

    def collect(
        self,
        workload: Mapping[str, Any] | None = None,
        *,
        namespace: str | None = None,
        kind: str | None = None,
        name: str | None = None,
        pod_labels: Mapping[str, str] | None = None,
        cluster: str = "unknown",
        observed_at: datetime | str | None = None,
    ) -> ScanResult:
        """Determine exposure without accessing any namespace except the approved one.

        Supplying ``workload`` is preferred.  The explicit identity and
        ``pod_labels`` form supports callers that already normalized workload
        evidence and prevents this collector from needing another Kubernetes
        API call.
        """

        if workload is not None:
            workload = _mapping(workload, "workload")
            metadata = _mapping(workload.get("metadata"), "workload.metadata")
            derived_namespace = _required_text(
                metadata.get("namespace"), "workload.metadata.namespace"
            )
            derived_kind = _required_text(workload.get("kind"), "workload.kind")
            derived_name = _required_text(
                metadata.get("name"), "workload.metadata.name"
            )
            derived_labels = _pod_labels(workload)
            for supplied, derived, field_name in (
                (namespace, derived_namespace, "namespace"),
                (kind, derived_kind, "kind"),
                (name, derived_name, "name"),
            ):
                if supplied is not None and supplied != derived:
                    raise ValueError(f"{field_name} does not match workload identity")
            if pod_labels is not None and dict(pod_labels) != derived_labels:
                raise ValueError("pod_labels do not match workload pod labels")
            namespace, kind, name, pod_labels = (
                derived_namespace,
                derived_kind,
                derived_name,
                derived_labels,
            )

        namespace = _required_text(namespace, "namespace")
        kind = _required_text(kind, "kind")
        name = _required_text(name, "name")
        cluster = _required_text(cluster, "cluster")
        pod_labels = _string_mapping(pod_labels, "pod_labels")

        if namespace != self.approved_namespace:
            raise PermissionError(
                f"namespace {namespace!r} is not the approved namespace "
                f"{self.approved_namespace!r}"
            )

        target = Target(cluster=cluster, namespace=namespace, kind=kind, name=name)
        try:
            raw_services = self._service_client.list_namespaced_service(
                namespace=namespace
            )
            services = _items(raw_services, "service list")

            matched_services: list[dict[str, Any]] = []
            classification = ExposureClassification.UNKNOWN
            for service in services:
                collected = _service_evidence(
                    service, namespace=namespace, pod_labels=pod_labels
                )
                if collected is not None:
                    evidence, candidate = collected
                    matched_services.append(evidence)
                    classification = _strongest(classification, candidate)

            # Ingress must still be listed when no Service matches so the
            # successful result proves both required namespace-scoped reads ran.
            raw_ingresses = self._ingress_client.list_namespaced_ingress(
                namespace=namespace
            )
            ingresses = _items(raw_ingresses, "ingress list")
            matched_service_names = {item["name"] for item in matched_services}
            matching_ingresses: list[dict[str, Any]] = []
            for ingress in ingresses:
                collected = _ingress_evidence(
                    ingress,
                    namespace=namespace,
                    matched_service_names=matched_service_names,
                )
                if collected is not None:
                    evidence, candidate = collected
                    matching_ingresses.append(evidence)
                    classification = _strongest(classification, candidate)

            if not matched_services:
                conclusion = "No Service selector matched the workload pod labels"
            elif classification is ExposureClassification.INTERNAL:
                conclusion = "Only internal reachability evidence was found"
            elif classification is ExposureClassification.POTENTIALLY_EXTERNAL:
                conclusion = "External reachability is possible but not confirmed"
            else:
                conclusion = (
                    "Assigned public endpoint evidence confirms external reachability"
                )

            evidence = Evidence(
                source=EVIDENCE_SOURCE,
                observed_at=observed_at or datetime.now(timezone.utc),
                collector_version=self.collector_version,
                details={
                    "workload": {
                        "cluster": cluster,
                        "namespace": namespace,
                        "kind": kind,
                        "name": name,
                        "podLabels": dict(pod_labels),
                    },
                    "classification": classification.value,
                    "conclusion": conclusion,
                    "services": matched_services,
                    "ingresses": matching_ingresses,
                },
            )
            return ScanResult(
                target=target,
                status=ScanStatus.COMPLETE,
                evidence=[evidence],
            )
        except Exception as exc:
            return ScanResult(
                target=target,
                status=ScanStatus.COLLECTION_FAILED,
                errors=[
                    f"failed to collect exposure for {kind} {namespace}/{name}: "
                    f"{type(exc).__name__}: {exc}"
                ],
            )


def collect_exposure(
    client: Any,
    workload: Mapping[str, Any] | None = None,
    *,
    approved_namespace: str,
    networking_client: Any | None = None,
    namespace: str | None = None,
    kind: str | None = None,
    name: str | None = None,
    pod_labels: Mapping[str, str] | None = None,
    cluster: str = "unknown",
    observed_at: datetime | str | None = None,
) -> ScanResult:
    """Convenience wrapper for one exposure collection."""

    return ExposureCollector(
        client,
        approved_namespace=approved_namespace,
        networking_client=networking_client,
    ).collect(
        workload,
        namespace=namespace,
        kind=kind,
        name=name,
        pod_labels=pod_labels,
        cluster=cluster,
        observed_at=observed_at,
    )
