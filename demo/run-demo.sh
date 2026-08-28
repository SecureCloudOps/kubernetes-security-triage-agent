#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly CLUSTER_CONTEXT="kind-ksta-demo"
readonly SCANNER_KUBECONFIG="${SCRIPT_DIR}/.generated/scanner.kubeconfig"
readonly REPORT_ROOT="${SCRIPT_DIR}/reports"

"${SCRIPT_DIR}/preflight.sh"

if ! kubectl --context "${CLUSTER_CONTEXT}" get namespace secure-demo >/dev/null 2>&1; then
  printf 'error: the ksta-demo cluster is not ready; run demo/setup.sh first\n' >&2
  exit 1
fi

"${SCRIPT_DIR}/create-scanner-kubeconfig.sh" "${SCANNER_KUBECONFIG}"

python_bin="${PYTHON_BIN:-}"
if [[ -n "${python_bin}" ]]; then
  python_bin="$(command -v "${python_bin}" 2>/dev/null || true)"
elif [[ -x "${PROJECT_ROOT}/.venv/bin/python" ]]; then
  python_bin="${PROJECT_ROOT}/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  python_bin="$(command -v python3)"
else
  python_bin="$(command -v python)"
fi

mkdir -p "${REPORT_ROOT}/secure-demo" "${REPORT_ROOT}/vulnerable-demo"

scan_status=0

run_scan() {
  local namespace="$1"
  local workload="$2"
  local output_dir="${REPORT_ROOT}/${namespace}"

  printf '\nScanning Deployment %s/%s\n' "${namespace}" "${workload}"
  if KUBECONFIG="${SCANNER_KUBECONFIG}" "${python_bin}" -m src.cli scan \
    --namespace "${namespace}" \
    --allowed-namespace "${namespace}" \
    --kind Deployment \
    --name "${workload}" \
    --output-dir "${output_dir}" \
    --fail-on none; then
    printf 'completed: %s\n' "${namespace}"
  else
    local exit_code=$?
    printf 'scan returned exit code %d: %s\n' "${exit_code}" "${namespace}" >&2
    scan_status=1
  fi
}

cd -- "${PROJECT_ROOT}"
run_scan secure-demo secure-web
run_scan vulnerable-demo vulnerable-web

printf '\nReports:\n'
printf '  secure:     %s\n' "${REPORT_ROOT}/secure-demo"
printf '  vulnerable: %s\n' "${REPORT_ROOT}/vulnerable-demo"
printf 'Cluster cleanup is manual: %s/cleanup.sh\n' "${SCRIPT_DIR}"

exit "${scan_status}"
