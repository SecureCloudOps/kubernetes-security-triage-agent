#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CLUSTER_NAME="ksta-demo"

if kind get clusters | grep -Fxq "${CLUSTER_NAME}"; then
  kind delete cluster --name "${CLUSTER_NAME}"
else
  printf 'Kind cluster %s does not exist\n' "${CLUSTER_NAME}"
fi

rm -rf -- "${SCRIPT_DIR}/.generated" "${SCRIPT_DIR}/reports"
printf 'Removed generated scanner credentials and reports\n'
