#!/usr/bin/env bash
set -euo pipefail

# Lab 12 evidence collector (Linux only).
# Runs Task 1-4 commands from labs/lab12.md and stores outputs under labs/lab12/*.

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${LAB_DIR}/../.." && pwd)"

SETUP_DIR="${LAB_DIR}/setup"
RUNC_DIR="${LAB_DIR}/runc"
KATA_DIR="${LAB_DIR}/kata"
ISOLATION_DIR="${LAB_DIR}/isolation"
BENCH_DIR="${LAB_DIR}/bench"
ANALYSIS_DIR="${LAB_DIR}/analysis"

SKIP_BUILD=0
SKIP_ASSETS=0
KEEP_CONTAINERS=0

usage() {
  cat <<'EOF'
Usage:
  bash labs/lab12/collect-evidence.sh [options]

Options:
  --skip-build       Skip build-kata-runtime.sh step
  --skip-assets      Skip install-kata-assets.sh step
  --keep-containers  Keep juice-runc container after the run
EOF
}

while (($#)); do
  case "$1" in
    --skip-build) SKIP_BUILD=1 ;;
    --skip-assets) SKIP_ASSETS=1 ;;
    --keep-containers) KEEP_CONTAINERS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
  shift
done

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

check_containerd_service() {
  local load_state
  local active_state

  load_state="$(sudo systemctl show -p LoadState --value containerd 2>/dev/null || true)"
  if [[ "${load_state}" != "loaded" ]]; then
    echo "containerd systemd unit is not available (LoadState=${load_state:-unknown})." >&2
    exit 1
  fi

  active_state="$(sudo systemctl show -p ActiveState --value containerd 2>/dev/null || true)"
  if [[ "${active_state}" != "active" ]]; then
    echo "containerd service is present but not active (ActiveState=${active_state:-unknown}); attempting start..." >&2
    sudo systemctl start containerd
    active_state="$(sudo systemctl show -p ActiveState --value containerd 2>/dev/null || true)"
    if [[ "${active_state}" != "active" ]]; then
      echo "Failed to activate containerd service via systemctl." >&2
      exit 1
    fi
  fi
}

cleanup() {
  if [[ "${KEEP_CONTAINERS}" -eq 0 ]]; then
    sudo nerdctl rm -f juice-runc >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script must run on Linux. Current OS: $(uname -s)" >&2
  exit 1
fi

need_cmd sudo
need_cmd containerd
need_cmd nerdctl
need_cmd systemctl
need_cmd journalctl
need_cmd jq
need_cmd curl
need_cmd awk
need_cmd ip
need_cmd uname
check_containerd_service

mkdir -p "${SETUP_DIR}" "${RUNC_DIR}" "${KATA_DIR}" "${ISOLATION_DIR}" "${BENCH_DIR}" "${ANALYSIS_DIR}"

vm_flags_count="$(egrep -c '(vmx|svm)' /proc/cpuinfo || true)"
if [[ "${vm_flags_count}" =~ ^[0-9]+$ ]] && (( vm_flags_count == 0 )); then
  echo "CPU virtualization flags not detected in /proc/cpuinfo (vmx|svm=0)." >&2
  echo "Enable hardware virtualization (or nested virtualization) before running Lab 12." >&2
  exit 1
fi

{
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host_uname=$(uname -a)"
  echo "cpu_virtualization_flags=${vm_flags_count}"
  echo "containerd_version=$(containerd --version)"
  echo "nerdctl_version=$(sudo nerdctl --version)"
} | tee "${ANALYSIS_DIR}/host-info.txt"

echo "[Task 1/4] Installing/configuring Kata runtime..."
if [[ "${SKIP_BUILD}" -eq 0 ]]; then
  bash "${LAB_DIR}/setup/build-kata-runtime.sh"
  sudo install -m 0755 "${LAB_DIR}/setup/kata-out/containerd-shim-kata-v2" /usr/local/bin/
fi

command -v containerd-shim-kata-v2 | tee "${SETUP_DIR}/kata-shim-path.txt"
containerd-shim-kata-v2 --version | tee "${SETUP_DIR}/kata-built-version.txt"

if [[ "${SKIP_ASSETS}" -eq 0 ]]; then
  sudo bash "${LAB_DIR}/scripts/install-kata-assets.sh"
fi

sudo bash "${LAB_DIR}/scripts/configure-containerd-kata.sh"
sudo systemctl restart containerd
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a | tee "${SETUP_DIR}/kata-smoke-test.txt"

echo "[Task 2/4] Runtime comparison (runc vs kata)..."
sudo nerdctl rm -f juice-runc >/dev/null 2>&1 || true
sudo nerdctl run -d --name juice-runc -p 3012:3000 bkimminich/juice-shop:v19.0.0 | tee "${RUNC_DIR}/container-id.txt"
sleep 15
curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012 | tee "${RUNC_DIR}/health.txt"

sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a | tee "${KATA_DIR}/test1.txt"
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r | tee "${KATA_DIR}/kernel.txt"
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1" | tee "${KATA_DIR}/cpu.txt"

{
  echo "=== Kernel Version Comparison ==="
  echo -n "Host kernel (runc uses this): "
  uname -r
  echo -n "Kata guest kernel: "
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 cat /proc/version
} | tee "${ANALYSIS_DIR}/kernel-comparison.txt"

{
  echo "=== CPU Model Comparison ==="
  echo "Host CPU:"
  grep "model name" /proc/cpuinfo | head -1
  echo "Kata VM CPU:"
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1"
} | tee "${ANALYSIS_DIR}/cpu-comparison.txt"

echo "[Task 3/4] Isolation tests..."
{
  echo "=== dmesg Access Test ==="
  echo "Kata VM (separate kernel boot logs):"
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 dmesg 2>&1 | head -5
} | tee "${ISOLATION_DIR}/dmesg.txt"

{
  echo "=== /proc Entries Count ==="
  echo -n "Host: "
  ls /proc | wc -l
  echo -n "Kata VM: "
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "ls /proc | wc -l"
} | tee "${ISOLATION_DIR}/proc.txt"

{
  echo "=== Network Interfaces ==="
  echo "Kata VM network:"
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 ip addr
} | tee "${ISOLATION_DIR}/network.txt"

{
  echo "=== Kernel Modules Count ==="
  echo -n "Host kernel modules: "
  ls /sys/module | wc -l
  echo -n "Kata guest kernel modules: "
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "ls /sys/module 2>/dev/null | wc -l"
} | tee "${ISOLATION_DIR}/modules.txt"

echo "[Task 4/4] Performance snapshot..."
{
  echo "=== Startup Time Comparison ==="
  echo "runc:"
  { /usr/bin/time -p sudo nerdctl run --rm alpine:3.19 echo "test" >/dev/null; } 2>&1 | awk '/^real/{print}'
  echo "Kata:"
  { /usr/bin/time -p sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 echo "test" >/dev/null; } 2>&1 | awk '/^real/{print}'
} | tee "${BENCH_DIR}/startup.txt"

curl_out="${BENCH_DIR}/curl-3012.txt"
: > "${curl_out}"
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{time_total}\n" http://localhost:3012/ >> "${curl_out}"
done

{
  echo "=== HTTP Latency Test (juice-runc) ==="
  echo "Results for port 3012 (juice-runc):"
  awk '
    NR==1 { min=$1; max=$1 }
    { sum+=$1; if($1<min) min=$1; if($1>max) max=$1 }
    END { if(NR>0) printf "avg=%.4fs min=%.4fs max=%.4fs n=%d\n", sum/NR, min, max, NR }
  ' "${curl_out}"
} | tee "${BENCH_DIR}/http-latency.txt"

echo "Done. Evidence collected under ${LAB_DIR}/"
echo "Next: update ${REPO_ROOT}/labs/submission12.md with findings from generated files."
