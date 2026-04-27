#!/usr/bin/env bash
set -euo pipefail

# Lab 12 evidence capture script.
# Runs all commands from labs/lab12.md and writes outputs under labs/lab12/.
#
# Usage:
#   bash labs/lab12/capture-lab12.sh
#
# Requirements:
#   - root privileges (sudo) for nerdctl + containerd runtime config
#   - containerd running
#   - curl, jq, awk, zstd (for kata-static install)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_DIR="${ROOT_DIR}/lab12"

mkdir -p "${LAB_DIR}"/{setup,runc,kata,isolation,bench,analysis}

log() { printf '\n== %s ==\n' "$*" >&2; }

log "Prereq: virtualization flags"
egrep -c '(vmx|svm)' /proc/cpuinfo | tee "${LAB_DIR}/setup/virt-flags.txt"

log "Task 1.1: build kata shim (runtime-rs)"
bash "${LAB_DIR}/setup/build-kata-runtime.sh" 2>&1 | tee "${LAB_DIR}/setup/kata-build.log"

log "Task 1.1: install kata shim (sudo)"
sudo install -m 0755 "${LAB_DIR}/setup/kata-out/containerd-shim-kata-v2" /usr/local/bin/
command -v containerd-shim-kata-v2 | tee "${LAB_DIR}/setup/kata-shim-path.txt"
containerd-shim-kata-v2 --version | tee "${LAB_DIR}/setup/kata-built-version.txt"

log "Task 1.1: install kata assets + default config (sudo)"
sudo bash "${LAB_DIR}/scripts/install-kata-assets.sh" 2>&1 | tee "${LAB_DIR}/setup/kata-assets-install.log"
sudo test -f /etc/kata-containers/runtime-rs/configuration.toml && echo "OK: /etc/kata-containers/runtime-rs/configuration.toml exists" \
  | tee "${LAB_DIR}/setup/kata-runtime-config-path.txt"

log "Task 1.2: configure containerd for kata runtime (sudo)"
sudo bash "${LAB_DIR}/scripts/configure-containerd-kata.sh" 2>&1 | tee "${LAB_DIR}/setup/containerd-kata-configure.log"
sudo systemctl restart containerd
sudo systemctl is-active containerd | tee "${LAB_DIR}/setup/containerd-active.txt"

log "Task 1: test kata runtime"
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a | tee "${LAB_DIR}/setup/kata-smoke-uname-a.txt"

log "Task 2.1: runc (default) - juice-shop"
sudo nerdctl rm -f juice-runc >/dev/null 2>&1 || true
sudo nerdctl run -d --name juice-runc -p 3012:3000 bkimminich/juice-shop:v19.0.0
sleep 10
curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012 | tee "${LAB_DIR}/runc/health.txt"

log "Task 2.2: kata short-lived alpine tests"
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a | tee "${LAB_DIR}/kata/test1.txt"
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -r | tee "${LAB_DIR}/kata/kernel.txt"
sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1" | tee "${LAB_DIR}/kata/cpu.txt"

log "Task 2.3: kernel comparison"
{
  echo "=== Kernel Version Comparison ==="
  echo -n "Host kernel (runc uses this): "
  uname -r
  echo -n "Kata guest kernel: "
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 cat /proc/version
} | tee "${LAB_DIR}/analysis/kernel-comparison.txt"

log "Task 2.4: CPU comparison"
{
  echo "=== CPU Model Comparison ==="
  echo "Host CPU:"
  grep "model name" /proc/cpuinfo | head -1
  echo "Kata VM CPU:"
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "grep 'model name' /proc/cpuinfo | head -1"
} | tee "${LAB_DIR}/analysis/cpu-comparison.txt"

log "Task 3.1: dmesg access test"
{
  echo "=== dmesg Access Test ==="
  echo "Kata VM (separate kernel boot logs):"
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 dmesg 2>&1 | head -5
} | tee "${LAB_DIR}/isolation/dmesg.txt"

log "Task 3.2: /proc entries count"
{
  echo "=== /proc Entries Count ==="
  echo -n "Host: "
  ls /proc | wc -l
  echo -n "Kata VM: "
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "ls /proc | wc -l"
} | tee "${LAB_DIR}/isolation/proc.txt"

log "Task 3.3: network interfaces in kata VM"
{
  echo "=== Network Interfaces ==="
  echo "Kata VM network:"
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 ip addr
} | tee "${LAB_DIR}/isolation/network.txt"

log "Task 3.4: kernel modules count"
{
  echo "=== Kernel Modules Count ==="
  echo -n "Host kernel modules: "
  ls /sys/module | wc -l
  echo -n "Kata guest kernel modules: "
  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 sh -c "ls /sys/module 2>/dev/null | wc -l"
} | tee "${LAB_DIR}/isolation/modules.txt"

log "Task 4.1: startup time comparison"
{
  echo "=== Startup Time Comparison ==="
  echo "runc:"
  ( time sudo nerdctl run --rm alpine:3.19 echo "test" ) 2>&1 | grep real
  echo "Kata:"
  ( time sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 echo "test" ) 2>&1 | grep real
} | tee "${LAB_DIR}/bench/startup.txt"

log "Task 4.2: HTTP latency test (juice-runc)"
out="${LAB_DIR}/bench/curl-3012.txt"
: > "$out"
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{time_total}\n" http://localhost:3012/ >> "$out"
done
{
  echo "=== HTTP Latency Test (juice-runc) ==="
  echo "Results for port 3012 (juice-runc):"
  # Keep the awk line aligned with the lab, but compute min/max safely.
  min=$(sort -n "$out" | head -1)
  max=$(sort -n "$out" | tail -1)
  awk -v min="$min" -v max="$max" '{s+=$1; n+=1} END {if(n>0) printf \"avg=%.4fs min=%.4fs max=%.4fs n=%d\\n\", s/n, min, max, n}' "$out"
} | tee "${LAB_DIR}/bench/http-latency.txt"

log "Cleanup: stop juice-runc"
sudo nerdctl rm -f juice-runc >/dev/null 2>&1 || true

log "Done. Evidence saved under labs/lab12/."

