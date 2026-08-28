#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CLUSTER_NAME="ksta-demo"
readonly CLUSTER_CONTEXT="kind-${CLUSTER_NAME}"

"${SCRIPT_DIR}/preflight.sh"

if kind get clusters | grep -Fxq "${CLUSTER_NAME}"; then
  printf 'error: Kind cluster %s already exists; run demo/cleanup.sh first\n' "${CLUSTER_NAME}" >&2
  exit 1
fi

kind create cluster \
  --name "${CLUSTER_NAME}" \
  --config "${SCRIPT_DIR}/kind-config.yaml"

kubectl --context "${CLUSTER_CONTEXT}" apply -f "${SCRIPT_DIR}/manifests/namespaces.yaml"
kubectl --context "${CLUSTER_CONTEXT}" apply -f "${SCRIPT_DIR}/manifests/scanner-rbac.yaml"
kubectl --context "${CLUSTER_CONTEXT}" apply -f "${SCRIPT_DIR}/manifests/secure-workload.yaml"
kubectl --context "${CLUSTER_CONTEXT}" apply -f "${SCRIPT_DIR}/manifests/vulnerable-workload.yaml"

kubectl --context "${CLUSTER_CONTEXT}" \
  --namespace secure-demo \
  rollout status deployment/secure-web \
  --timeout=180s
kubectl --context "${CLUSTER_CONTEXT}" \
  --namespace vulnerable-demo \
  rollout status deployment/vulnerable-web \
  --timeout=180s

"${SCRIPT_DIR}/create-scanner-kubeconfig.sh"

printf '\nDemo cluster is ready. Run scans with: %s/run-demo.sh\n' "${SCRIPT_DIR}"
printf 'Cleanup remains manual: %s/cleanup.sh\n' "${SCRIPT_DIR}"
