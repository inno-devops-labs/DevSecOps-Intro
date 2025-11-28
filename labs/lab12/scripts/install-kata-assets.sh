#!/usr/bin/env bash
set -euo pipefail

VERSION="${KATA_VERSION:-3.23.0}"
ARCH="amd64"

TMP_DIR="$(mktemp -d)"
cd "$TMP_DIR"

echo "[lab12] Downloading kata-static-${VERSION}-${ARCH}.tar.zst ..."
curl -L -o kata-static.tar.zst "https://github.com/kata-containers/kata-containers/releases/download/${VERSION}/kata-static-${VERSION}-${ARCH}.tar.zst"

echo "[lab12] Extracting kata-static into / ..."
sudo tar --zstd -xvf kata-static.tar.zst

echo "[lab12] Kata static installed under /opt/kata"

sudo mkdir -p /etc/kata-containers /etc/kata-containers/runtime-rs

if [ -f /opt/kata/share/defaults/kata-containers/configuration.toml ]; then
  echo "[lab12] Installing default config to /etc/kata-containers"
  sudo cp /opt/kata/share/defaults/kata-containers/configuration.toml /etc/kata-containers/configuration.toml
fi

if [ -f /opt/kata/share/defaults/kata-containers/runtime-rs/configuration.toml ]; then
  echo "[lab12] Installing runtime-rs config to /etc/kata-containers/runtime-rs"
  sudo cp /opt/kata/share/defaults/kata-containers/runtime-rs/configuration.toml /etc/kata-containers/runtime-rs/configuration.toml
fi

echo "[lab12] Done installing Kata assets and configs."
