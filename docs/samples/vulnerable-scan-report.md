# Sanitized Kubernetes Security Scan Excerpt

**No exploitation was confirmed by this scan.** This committed example is shortened to one confirmed finding and one plausible attack path. Complete runtime reports remain local.

## Target and status

| Field | Value |
| --- | --- |
| Scan date | 2026-08-29 |
| Cluster | `ksta-demo` |
| Target | `Deployment vulnerable-demo/vulnerable-web` |
| Scan status | `COMPLETE` |
| Confirmed findings | 174 |
| Plausible attack paths | 3 |
| AI status | `DISABLED` in this run; validated separately |

## Severity summary

| Critical | High | Medium | Low | Info |
| ---: | ---: | ---: | ---: | ---: |
| 39 | 127 | 1 | 7 | 0 |

## Confirmed finding

### KSA-019343407670: CVE-2020-36330 affects libwebp6 in nginx:1.16.1

| Severity | Score | Confidence | Status |
| --- | ---: | --- | --- |
| Critical | 80 | High | `CONFIRMED` |

Trivy identified `libwebp6` version `0.6.1-2` in `nginx:1.16.1` at image digest `sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c`. The reported fixed version is `0.6.1-2+deb10u1`.

**Limitation:** The package vulnerability does not establish runtime reachability or exploitability.

## Plausible attack path

### KAP-a4b87e1a0758: External exposure combines with privileged or root execution

| Severity | Score | Status |
| --- | ---: | --- |
| High | 55 | `PLAUSIBLE` |

Supporting risk factors: `potential_external_exposure`, `privileged_container`, and `runs_as_root`.

**Limitation:** NodePort is potentially external. Public reachability, access, compromise, and exploitation were not confirmed.
