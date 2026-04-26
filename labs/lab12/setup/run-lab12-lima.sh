#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
cd "${ROOT_DIR}"

mkdir -p lab12/{setup,runc,kata,isolation,bench,analysis}

uname -r > lab12/analysis/host-kernel.txt
awk -F: '/model name|Hardware|Processor/ {gsub(/^[ \t]+/, "", $2); print $1 ": " $2; found=1; exit} END {if (!found) print "CPU info unavailable"}' /proc/cpuinfo > lab12/analysis/host-cpu.txt
ls /proc | wc -l > lab12/isolation/host-proc-count.txt
ls /sys/module | wc -l > lab12/isolation/host-modules-count.txt
ip addr > lab12/isolation/host-network.txt
sudo dmesg | head -20 > lab12/isolation/host-dmesg-head.txt || true

{
  echo "=== kata smoke failure ==="
  date -Iseconds
  sudo nerdctl run --rm --net=none --runtime io.containerd.kata.v2 alpine:3.19 echo kata-test
} > lab12/setup/kata-smoke-failure.txt 2>&1 || true

sudo journalctl -u containerd --since "5 minutes ago" --no-pager | tail -200 > lab12/setup/containerd-kata-journal-tail.txt || true

sudo nerdctl rm -f juice-runc >/dev/null 2>&1 || true
sudo nerdctl run -d --name juice-runc -p 3012:3000 bkimminich/juice-shop:v19.0.0 > lab12/runc/container-id.txt

for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3012 || true)"
  if [[ "${code}" == "200" ]]; then
    break
  fi
  sleep 2
done

curl -s -o /dev/null -w "juice-runc: HTTP %{http_code}\n" http://localhost:3012 | tee lab12/runc/health.txt
cp lab12/analysis/host-kernel.txt lab12/runc/kernel.txt
cp lab12/analysis/host-cpu.txt lab12/runc/cpu.txt

{
  echo "=== Startup Time Comparison ==="
  echo "runc:"
} > lab12/bench/startup.txt

/usr/bin/time -p sudo nerdctl run --rm alpine:3.19 echo test >> lab12/bench/startup.txt 2>&1

{
  echo
  echo "kata:"
  /usr/bin/time -p sudo nerdctl run --rm --net=none --runtime io.containerd.kata.v2 alpine:3.19 echo test
} >> lab12/bench/startup.txt 2>&1 || true

out="lab12/bench/curl-3012.txt"
: > "${out}"
for _ in $(seq 1 20); do
  curl -s -o /dev/null -w "%{time_total}\n" http://localhost:3012/ >> "${out}"
done

{
  echo "=== HTTP Latency Test (juice-runc) ==="
  echo "Results for port 3012 (juice-runc):"
  awk 'NR==1{min=$1;max=$1} {s+=$1;n+=1;if($1<min)min=$1;if($1>max)max=$1} END {if(n>0) printf "avg=%.4fs min=%.4fs max=%.4fs n=%d\n", s/n, min, max, n}' "${out}"
} | tee lab12/bench/http-latency.txt
