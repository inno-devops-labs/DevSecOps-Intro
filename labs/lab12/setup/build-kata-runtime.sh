#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/labs/lab12/setup/kata-out"

SRC=""

if [ -x /opt/kata/bin/containerd-shim-kata-v2 ]; then
  SRC="/opt/kata/bin/containerd-shim-kata-v2"
elif [ -x /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 ]; then
  SRC="/opt/kata/runtime-rs/bin/containerd-shim-kata-v2"
else
  echo "[lab12] ERROR: containerd-shim-kata-v2 not found under /opt/kata."
  echo "[lab12] Make sure you ran 'sudo bash labs/lab12/scripts/install-kata-assets.sh' successfully."
  exit 1
fi

mkdir -p "${OUT_DIR}"
cp "${SRC}" "${OUT_DIR}/containerd-shim-kata-v2"
echo "[lab12] Copied ${SRC} -> ${OUT_DIR}/containerd-shim-kata-v2"
