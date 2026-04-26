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

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
WORK_DIR="${ROOT_DIR}/lab12/setup/kata-build"
OUT_DIR="${ROOT_DIR}/lab12/setup/kata-out"
CONTAINER_CMD="${CONTAINER_CMD:-docker}"

mkdir -p "${WORK_DIR}" "${OUT_DIR}"

echo "Building Kata runtime with ${CONTAINER_CMD}..." >&2
"${CONTAINER_CMD}" run --rm \
  -e CARGO_NET_GIT_FETCH_WITH_CLI=true \
  -v "${WORK_DIR}":/work \
  -v "${OUT_DIR}":/out \
  rust:1.75-bookworm bash -lc '
    set -euo pipefail
    apt-get update && apt-get install -y --no-install-recommends \
      git jq make gcc g++ cmake pkg-config ca-certificates musl-tools libseccomp-dev && \
      update-ca-certificates || true

    # Ensure cargo/rustup are available
    export PATH=/usr/local/cargo/bin:$PATH
    rustc --version; cargo --version; rustup --version || true

    cd /work
    if [ ! -d kata-containers ]; then
      git clone --depth 1 https://github.com/kata-containers/kata-containers.git
    fi
    cd kata-containers/src/runtime-rs

    # Add the MUSL target matching the container architecture.
    case "$(uname -m)" in
      x86_64|amd64)
        RUST_TARGET=x86_64-unknown-linux-musl
        BUILD_LIBC=musl
        ;;
      aarch64|arm64)
        # The default Kata musl build expects aarch64-linux-musl-g++, which is
        # not provided by the base Debian image. Use the native GNU target on
        # arm64 so the shim can still be built reproducibly in this container.
        RUST_TARGET=aarch64-unknown-linux-gnu
        BUILD_LIBC=gnu
        ;;
      *)
        echo "ERROR: unsupported build architecture $(uname -m)" >&2
        exit 1
        ;;
    esac
    rustup target add "${RUST_TARGET}" || true

    # Build the runtime (shim v2)
    make LIBC="${BUILD_LIBC}"

    # Collect the produced binary
    f=$(find target -type f -name containerd-shim-kata-v2 | head -n1)
    if [ -z "$f" ]; then
      echo "ERROR: built binary not found" >&2; exit 1
    fi
    install -m 0755 "$f" /out/containerd-shim-kata-v2
    strip /out/containerd-shim-kata-v2 || true
    /out/containerd-shim-kata-v2 --version || true
  '

echo "Done. Binary saved to: ${OUT_DIR}/containerd-shim-kata-v2" >&2
