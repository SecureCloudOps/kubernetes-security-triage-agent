#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly CLUSTER_NAME="ksta-demo"
readonly ADMIN_CONTEXT="kind-${CLUSTER_NAME}"
readonly SCANNER_NAMESPACE="secure-demo"
readonly SCANNER_SERVICE_ACCOUNT="ksta-scanner"
readonly OUTPUT_PATH="${1:-${SCRIPT_DIR}/.generated/scanner.kubeconfig}"

python_bin="${PYTHON_BIN:-}"
if [[ -n "${python_bin}" ]]; then
  python_bin="$(command -v "${python_bin}" 2>/dev/null || true)"
elif [[ -x "${PROJECT_ROOT}/.venv/bin/python" ]]; then
  python_bin="${PROJECT_ROOT}/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  python_bin="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  python_bin="$(command -v python)"
fi

if [[ -z "${python_bin}" || ! -x "${python_bin}" ]]; then
  printf 'error: Python is required to decode the cluster CA certificate\n' >&2
  exit 1
fi

if ! kubectl --context "${ADMIN_CONTEXT}" get namespace "${SCANNER_NAMESPACE}" >/dev/null 2>&1; then
  printf 'error: cluster context %s is unavailable or the demo is not set up\n' "${ADMIN_CONTEXT}" >&2
  exit 1
fi

output_dir="$(dirname -- "${OUTPUT_PATH}")"
mkdir -p "${output_dir}"

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/ksta-scanner-kubeconfig.XXXXXX")"
cleanup_temp() {
  rm -rf -- "${temp_dir}"
}
trap cleanup_temp EXIT

temp_kubeconfig="${temp_dir}/scanner.kubeconfig"
ca_file="${temp_dir}/ca.crt"

cluster_server="$(
  kubectl config view \
    --raw \
    --minify \
    --context "${ADMIN_CONTEXT}" \
    --output 'jsonpath={.clusters[0].cluster.server}'
)"
ca_data="$(
  kubectl config view \
    --raw \
    --minify \
    --context "${ADMIN_CONTEXT}" \
    --output 'jsonpath={.clusters[0].cluster.certificate-authority-data}'
)"
scanner_token="$(
  kubectl --context "${ADMIN_CONTEXT}" \
    --namespace "${SCANNER_NAMESPACE}" \
    create token "${SCANNER_SERVICE_ACCOUNT}" \
    --duration=1h
)"

if [[ -z "${cluster_server}" || -z "${ca_data}" || -z "${scanner_token}" ]]; then
  printf 'error: failed to collect kubeconfig inputs\n' >&2
  exit 1
fi

printf '%s' "${ca_data}" | "${python_bin}" -c \
  'import base64, sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read()))' \
  >"${ca_file}"

kubectl --kubeconfig "${temp_kubeconfig}" config set-cluster "${CLUSTER_NAME}" \
  --server "${cluster_server}" \
  --certificate-authority "${ca_file}" \
  --embed-certs=true >/dev/null
kubectl --kubeconfig "${temp_kubeconfig}" config set-credentials "${SCANNER_SERVICE_ACCOUNT}" \
  --token "${scanner_token}" >/dev/null
kubectl --kubeconfig "${temp_kubeconfig}" config set-context "${CLUSTER_NAME}" \
  --cluster "${CLUSTER_NAME}" \
  --user "${SCANNER_SERVICE_ACCOUNT}" \
  --namespace "${SCANNER_NAMESPACE}" >/dev/null
kubectl --kubeconfig "${temp_kubeconfig}" config use-context "${CLUSTER_NAME}" >/dev/null

chmod 600 "${temp_kubeconfig}"
mv -f -- "${temp_kubeconfig}" "${OUTPUT_PATH}"
chmod 600 "${OUTPUT_PATH}"

printf 'scanner kubeconfig: %s (token expires in approximately 1 hour)\n' "${OUTPUT_PATH}"
