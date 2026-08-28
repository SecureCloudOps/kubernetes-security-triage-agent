# Security Contract

## Purpose

Given an approved Kubernetes workload, produce a repeatable,
evidence-backed security report without modifying the cluster.

## Supported targets

- Pod
- Deployment
- StatefulSet
- DaemonSet
- Service
- Ingress

Each scan must include an explicit namespace and workload name.

## Allowed operations

- Read approved workload metadata and specifications.
- Read Service and Ingress configuration for the target.
- Read RBAC rules connected to the target ServiceAccount.
- Read NetworkPolicies that may select the target.
- Run Trivy against container image references.
- Generate local JSON and Markdown reports.

## Prohibited operations

- Read Kubernetes Secret values.
- Create, update, patch, or delete Kubernetes resources.
- Execute commands inside containers.
- Read pod logs.
- Port-forward to workloads.
- Scan namespaces not explicitly approved.
- Run arbitrary shell commands supplied by the model.
- Automatically remediate findings.

## Required evidence

Every confirmed finding must contain:

- cluster identifier
- namespace
- workload kind and name
- affected container or Kubernetes resource
- source field or scanner result
- collection timestamp
- collector version

Vulnerability findings must also contain:

- image reference and digest when available
- CVE identifier
- affected package and installed version
- vulnerability severity
- fixed version when available

## Responsibility boundaries

Deterministic code decides:

- whether a security control is present
- whether a policy is violated
- the base risk score
- the severity produced from that score

The AI analyst may:

- correlate confirmed findings
- explain plausible attack paths
- describe blast radius
- prioritize remediation
- rewrite technical results for readability

The AI analyst must not:

- invent evidence
- change deterministic severity or score
- claim exploitation occurred
- call Kubernetes or shell tools directly
- recommend changes unrelated to collected evidence

## Failure behavior

- Missing required evidence produces `INSUFFICIENT_EVIDENCE`.
- Collector errors produce `COLLECTION_FAILED`.
- Invalid model output produces `ANALYSIS_FAILED`.
- A partial scan must be clearly labeled `PARTIAL`.
- No failed component may silently return a clean result.

## Definition of success

- Vulnerable fixtures are detected by deterministic rules.
- Secure fixtures produce no critical false positives.
- Identical evidence produces identical findings and scores.
- Every finding contains traceable evidence.
- Reports conform to the finding schema.
- Tests prove prohibited Kubernetes operations are unavailable.

