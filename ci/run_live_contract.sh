#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

workspace="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${workspace}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${workspace}/target}"
# Keep the local fixtures off any CI runner's HTTP proxy.
export no_proxy="${no_proxy:+${no_proxy},}${NO_PROXY:+${NO_PROXY},}127.0.0.1,localhost,::1"
export NO_PROXY="${no_proxy}"

# Compile before starting the readiness deadline.
cargo build --locked -p tempest-ignition --bin tempest

run_dir="$(mktemp -d "${TMPDIR:-/tmp}/tempest-contract.XXXXXX")"
case "${run_dir}" in
  "${TMPDIR:-/tmp}"/tempest-contract.*) ;;
  *)
    echo "Refusing an unexpected contract workspace path" >&2
    exit 2
    ;;
esac
server_pid=""

cleanup() {
  local status=$?
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  if ((status != 0)) && [[ -f "${run_dir}/tempest.log" ]]; then
    cat "${run_dir}/tempest.log"
  fi
  rm -rf -- "${run_dir}"
  return "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "${run_dir}/tftpboot"
printf 'tempest live contract v1\n' >"${run_dir}/tftpboot/contract-v1.bin"
printf 'tempest live contract v2\n' >"${run_dir}/tftpboot/contract-v2.bin"
cat >"${run_dir}/tempest.toml" <<EOF
[server]
bind = "127.0.0.1"
port = 0
root = "${run_dir}/tftpboot"
max_boot_sessions = 1

[api]
bind = "127.0.0.1"
# The server binds an ephemeral port itself and logs it; probing for a free
# port here would race any other process for it before the server binds.
port = 0
enable_metrics = true
enable_versions_api = true
enable_audit_api = false
api_key = "contract-test-key-2026"
EOF

"${CARGO_TARGET_DIR}/debug/tempest" --config "${run_dir}/tempest.toml" >"${run_dir}/tempest.log" 2>&1 &
server_pid=$!

api_url=""
for _ in {1..90}; do
  if [[ -z "${api_url}" ]]; then
    api_addr="$(grep 'HTTP server listening' "${run_dir}/tempest.log" \
      | grep -oE '127\.0\.0\.1:[0-9]+' | head -n 1 || true)"
    [[ -n "${api_addr}" ]] && api_url="http://${api_addr}"
  fi
  if [[ -n "${api_url}" ]] && curl --fail --silent "${api_url}/ready" >/dev/null; then
    break
  fi
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    cat "${run_dir}/tempest.log"
    exit 1
  fi
  sleep 1
done
if [[ -z "${api_url}" ]]; then
  echo "Tempest did not report its HTTP listener address" >&2
  exit 1
fi
curl --fail --silent --show-error "${api_url}/ready" >/dev/null

TEMPEST_TEST_BASE_URL="${api_url}" \
TEMPEST_TEST_API_KEY=contract-test-key-2026 \
TEMPEST_TEST_ARTIFACT_PATH="${run_dir}/tftpboot/contract-v1.bin" \
TEMPEST_TEST_REPLACEMENT_PATH="${run_dir}/tftpboot/contract-v2.bin" \
  cargo test --locked \
    -p tempest-control-client \
    --test live_contract -- --ignored

echo "tempest=$(git -C "${workspace}" rev-parse HEAD)"
