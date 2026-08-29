# Kubernetes Security Analyst

A read-only security analysis tool for Kubernetes workloads.

## Current milestone

Milestone 1 defines the security contract:

- supported Kubernetes resources
- permitted and prohibited operations
- required evidence
- deterministic risk scoring
- report structure
- failure behavior

## Planned flow

1. Collect evidence from Kubernetes and Trivy.
2. Normalize evidence into a stable schema.
3. Apply deterministic security rules.
4. Use AI to explain and prioritize confirmed findings.
5. Generate JSON and Markdown reports.

## Safety rule

The system is read-only. It never reads Secret values, executes inside pods,
or modifies Kubernetes resources.

