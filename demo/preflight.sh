#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

failures=0

require_command() {
  local command_name="$1"
  if command -v "${command_name}" >/dev/null 2>&1; then
    printf 'ok: %s\n' "${command_name}"
  else
    printf 'missing: %s\n' "${command_name}" >&2
    failures=$((failures + 1))
  fi
}

for command_name in docker kind kubectl trivy; do
  require_command "${command_name}"
done

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
  printf 'missing: Python 3.11 or newer\n' >&2
  failures=$((failures + 1))
else
  if "${python_bin}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    printf 'ok: Python (%s)\n' "${python_bin}"
  else
    printf 'invalid: Python 3.11 or newer is required (%s)\n' "${python_bin}" >&2
    failures=$((failures + 1))
  fi

  if "${python_bin}" -c 'import jsonschema, kubernetes, yaml' >/dev/null 2>&1; then
    printf 'ok: Python dependencies (jsonschema, kubernetes, yaml)\n'
  else
    printf 'missing: required Python packages (jsonschema, kubernetes, yaml)\n' >&2
    failures=$((failures + 1))
  fi
fi

if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    printf 'ok: Docker daemon is reachable\n'
  else
    printf 'unavailable: Docker daemon is not reachable\n' >&2
    failures=$((failures + 1))
  fi
fi

if ((failures > 0)); then
  printf 'preflight failed with %d problem(s)\n' "${failures}" >&2
  exit 1
fi

printf 'preflight passed\n'
