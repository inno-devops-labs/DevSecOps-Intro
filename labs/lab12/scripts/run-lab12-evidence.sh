#!/usr/bin/env bash
set -euo pipefail

# Run Lab 12 evidence collection on a Linux host with KVM access.
# This script intentionally refuses to run on macOS/Docker Desktop without /dev/kvm
# so the submission evidence is not accidentally fabricated from an incompatible host.

ROOT_DIR="$(git rev-parse --show-toplevel)"
RESULTS_DIR="${ROOT_DIR}/labs/lab12/results"
KATA_RUNTIME="io.containerd.kata.v2"
IMAGE="alpine:3.20"

mkdir -p "${RESULTS_DIR}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_linux_kvm() {
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Lab 12 requires Linux with KVM; current OS is $(uname -s)." >&2
    exit 1
  fi

  if [[ ! -e /dev/kvm ]]; then
    echo "Lab 12 requires /dev/kvm; it is not present on this host." >&2
    exit 1
  fi
}

runtime_flag() {
  case "$1" in
    runc) printf '' ;;
    kata) printf -- '--runtime=%s' "${KATA_RUNTIME}" ;;
    *) echo "unknown runtime: $1" >&2; exit 1 ;;
  esac
}

run_container() {
  local runtime="$1"
  shift
  local flag
  flag="$(runtime_flag "${runtime}")"
  # shellcheck disable=SC2086
  sudo nerdctl run --rm ${flag} "${IMAGE}" "$@"
}

collect_host_info() {
  uname -a | tee "${RESULTS_DIR}/host-kernel.txt"
  ls -la /dev/kvm | tee "${RESULTS_DIR}/host-kvm.txt"
  containerd --version | tee "${RESULTS_DIR}/containerd-version.txt"
  nerdctl --version | tee "${RESULTS_DIR}/nerdctl-version.txt"
}

install_kata() {
  sudo bash "${ROOT_DIR}/labs/lab12/scripts/install-kata-assets.sh"
  sudo bash "${ROOT_DIR}/labs/lab12/scripts/configure-containerd-kata.sh"
  sudo systemctl restart containerd

  grep -A 3 'runtimes.kata' /etc/containerd/config.toml \
    | tee "${RESULTS_DIR}/containerd-kata-config.txt"
  cat /opt/kata/VERSION | tee "${RESULTS_DIR}/kata-version.txt"
}

collect_kernel_evidence() {
  run_container runc sh -c "uname -a; head -3 /proc/cpuinfo" \
    > "${RESULTS_DIR}/runc-kernel.txt" 2>&1
  run_container kata sh -c "uname -a; head -3 /proc/cpuinfo" \
    > "${RESULTS_DIR}/kata-kernel.txt" 2>&1
}

collect_isolation_evidence() {
  run_container runc ls /dev > "${RESULTS_DIR}/runc-devs.txt"
  run_container kata ls /dev > "${RESULTS_DIR}/kata-devs.txt"
  diff "${RESULTS_DIR}/runc-devs.txt" "${RESULTS_DIR}/kata-devs.txt" \
    > "${RESULTS_DIR}/dev-diff.txt" || true

  run_container runc sh -c "grep ^Cap /proc/1/status" \
    > "${RESULTS_DIR}/runc-caps.txt"
  run_container kata sh -c "grep ^Cap /proc/1/status" \
    > "${RESULTS_DIR}/kata-caps.txt"
}

collect_benchmarks() {
  for runtime in runc kata; do
    echo "=== ${runtime} ==="
    for i in 1 2 3 4 5; do
      start="$(date +%s.%N)"
      run_container "${runtime}" echo "hello" >/dev/null
      end="$(date +%s.%N)"
      awk -v i="${i}" -v start="${start}" -v end="${end}" \
        'BEGIN { printf "%s: %.3f s\n", i, end - start }'
    done
  done | tee "${RESULTS_DIR}/startup-bench.txt"

  for runtime in runc kata; do
    echo "=== ${runtime} I/O ==="
    run_container "${runtime}" sh -c 'dd if=/dev/zero of=/dev/null bs=1M count=100 2>&1' \
      | grep "copied"
  done | tee "${RESULTS_DIR}/io-bench.txt"
}

collect_escape_poc() {
  echo "original" | sudo tee /tmp/lab12-target >/dev/null
  sudo chown root:root /tmp/lab12-target

  sudo nerdctl run --rm --privileged -v /tmp:/host_tmp "${IMAGE}" \
    sh -c 'echo "OVERWRITTEN BY RUNC CONTAINER" > /host_tmp/lab12-target && cat /host_tmp/lab12-target' \
    > "${RESULTS_DIR}/runc-escape-output.txt" 2>&1
  sudo cat /tmp/lab12-target > "${RESULTS_DIR}/runc-escape-host-verify.txt"

  echo "original" | sudo tee /tmp/lab12-target >/dev/null
  sudo nerdctl run --rm --runtime="${KATA_RUNTIME}" --privileged -v /tmp:/host_tmp "${IMAGE}" \
    sh -c 'echo "ATTEMPTED OVERWRITE FROM KATA" > /host_tmp/lab12-target 2>&1 && cat /host_tmp/lab12-target; echo "---host view must be verified outside---"' \
    > "${RESULTS_DIR}/kata-escape-attempt.txt" 2>&1 || true
  sudo cat /tmp/lab12-target > "${RESULTS_DIR}/kata-escape-host-verify.txt"
}

main() {
  require_linux_kvm
  require_cmd sudo
  require_cmd containerd
  require_cmd nerdctl
  require_cmd awk
  require_cmd grep

  collect_host_info
  install_kata
  collect_kernel_evidence
  collect_isolation_evidence
  collect_benchmarks
  collect_escape_poc

  echo "Lab 12 evidence written to ${RESULTS_DIR}" >&2
}

main "$@"
