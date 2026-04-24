#!/usr/bin/env bash
set -euo pipefail

# Build Kata Containers 3.x Rust runtime (containerd-shim-kata-v2)
# inside a temporary Rust toolchain container, and place the binary
# into the provided output directory. This avoids installing build
# dependencies on the host.
#
# Usage:
#   bash labs/lab12/setup/build-kata-runtime.sh
#   # result: labs/lab12/setup/kata-out/containerd-shim-kata-v2

KATA_VER="${KATA_VER:-3.29.0}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
OUT_DIR="${ROOT_DIR}/lab12/setup/kata-out"

mkdir -p "${OUT_DIR}"

echo "Building Kata Containers ${KATA_VER} runtime in Docker..." >&2
docker run --rm \
  -e CARGO_NET_GIT_FETCH_WITH_CLI=true \
  -e KATA_VER="${KATA_VER}" \
  -v "${OUT_DIR}":/out \
  rust:1.92-bookworm bash -c '
    set -e
    export PATH=/usr/local/cargo/bin:$PATH

    apt-get update -qq && apt-get install -y -q --no-install-recommends \
      git make gcc pkg-config ca-certificates \
      musl-tools libseccomp-dev clang jq libclang-dev \
      protobuf-compiler cmake zlib1g-dev 2>/dev/null

    echo "Cloning kata-containers ${KATA_VER}..." >&2
    git clone --depth 1 --branch "${KATA_VER}" \
      https://github.com/kata-containers/kata-containers.git /tmp/kata 2>/dev/null

    cd /tmp/kata/src/runtime-rs
    echo "Building (this takes ~5-10 minutes)..." >&2
    make LIBC=gnu

    f=$(find /tmp/kata/target -type f -name containerd-shim-kata-v2 | head -1)
    if [ -z "$f" ]; then
      echo "ERROR: built binary not found" >&2; exit 1
    fi
    install -m 0755 "$f" /out/containerd-shim-kata-v2
    /out/containerd-shim-kata-v2 --version
  '

echo "Done. Binary saved to: ${OUT_DIR}/containerd-shim-kata-v2" >&2
