#!/usr/bin/env bash
set -euo pipefail

r="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
w="${r}/lab12/setup/kata-build"
o="${r}/lab12/setup/kata-out"

mkdir -p "$w" "$o"

docker run --rm \
  -e CARGO_NET_GIT_FETCH_WITH_CLI=true \
  -v "$w":/work \
  -v "$o":/out \
  rust:1.75-bookworm bash -lc '
    set -euo pipefail
    apt-get update && apt-get install -y --no-install-recommends \
      git make gcc pkg-config ca-certificates musl-tools libseccomp-dev && \
      update-ca-certificates || true

    export PATH=/usr/local/cargo/bin:$PATH

    cd /work
    if [ ! -d kata-containers ]; then
      git clone --depth 1 https://github.com/kata-containers/kata-containers.git
    fi
    cd kata-containers/src/runtime-rs

    rustup target add x86_64-unknown-linux-musl || true

    make

    bin=$(find target -type f -name containerd-shim-kata-v2 | head -n1)
    if [[ -z "$bin" ]]; then
      exit 1
    fi
    install -m 0755 "$bin" /out/containerd-shim-kata-v2
    strip /out/containerd-shim-kata-v2 || true
  '
