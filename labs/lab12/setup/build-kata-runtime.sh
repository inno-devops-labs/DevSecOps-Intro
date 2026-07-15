#!/usr/bin/env bash
set -euo pipefail

# Build the Kata containerd shim in a Rust container.
# Result: labs/lab12/setup/kata-out/containerd-shim-kata-v2

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="${ROOT_DIR}/labs/lab12/setup/kata-build"
OUT_DIR="${ROOT_DIR}/labs/lab12/setup/kata-out"

mkdir -p "${WORK_DIR}" "${OUT_DIR}"

docker run --rm   -v "${WORK_DIR}":/work   -v "${OUT_DIR}":/out   rust:1.75-bookworm bash -lc '
    set -euo pipefail
    apt-get update && apt-get install -y --no-install-recommends git make gcc pkg-config ca-certificates musl-tools libseccomp-dev
    export PATH=/usr/local/cargo/bin:$PATH
    cd /work
    if [ ! -d kata-containers ]; then
      git clone --depth 1 https://github.com/kata-containers/kata-containers.git
    fi
    cd kata-containers/src/runtime-rs
    rustup target add x86_64-unknown-linux-musl || true
    make
    f=$(find target -type f -name containerd-shim-kata-v2 | head -n1)
    install -m 0755 "$f" /out/containerd-shim-kata-v2
  '

echo "Done. Binary: ${OUT_DIR}/containerd-shim-kata-v2"
