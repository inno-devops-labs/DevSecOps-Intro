#!/usr/bin/env bash
set -euo pipefail

# install-kata-assets.sh
# Download and install Kata Containers static assets (kernel, rootfs image,
# default runtime-rs configuration) under /opt/kata, and ensure a
# configuration file exists in an expected path for runtime-rs.
#
# Usage:
#   sudo bash labs/lab12/scripts/install-kata-assets.sh [KATA_VER]
#
# Notes:
# - Requires: curl, jq, tar (with zstd support), and root privileges.
# - Creates or updates a symlink at:
#     /etc/kata-containers/runtime-rs/configuration.toml
#   pointing to the installed default configuration.

VER_ARG=${1:-}
ARCH=$(uname -m)
case ${ARCH} in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [[ -n "${VER_ARG}" ]]; then
  KATA_VER=$(echo "${VER_ARG}" | sed -E 's/^v//')
else
  KATA_VER=$(curl -fsSL https://api.github.com/repos/kata-containers/kata-containers/releases/latest | jq -r .tag_name)
  KATA_VER=${KATA_VER#v}
fi

ASSET_URL="https://github.com/kata-containers/kata-containers/releases/download/${KATA_VER}/kata-static-${KATA_VER}-${ARCH}.tar.zst"

echo "Installing Kata static assets ${KATA_VER} for ${ARCH}" >&2
TMP_TAR=$(mktemp --suffix=.tar.zst)
curl -fL -o "${TMP_TAR}" "${ASSET_URL}"

# Extract to root; archive lays files under /opt/kata, /usr/local/bin, etc.
# Prefer explicit decompressor if available to avoid tar invoking external zstd unexpectedly.
if command -v zstd >/dev/null 2>&1; then
  zstd -d -c "${TMP_TAR}" | tar -xf - -C /
elif command -v unzstd >/dev/null 2>&1; then
  unzstd -c "${TMP_TAR}" | tar -xf - -C /
elif tar --help 2>/dev/null | grep -q -- '--zstd'; then
  tar --zstd -xf "${TMP_TAR}" -C /
else
  echo "Missing zstd support to extract ${TMP_TAR}." >&2
  echo "Install the zstd package (e.g., sudo apt-get update && sudo apt-get install -y zstd) and re-run." >&2
  exit 1
fi
rm -f "${TMP_TAR}"

# Link configuration to an expected path for runtime-rs
# Prefer QEMU (KVM-backed, most compatible with our shim built without embedded dragonball)
mkdir -p /etc/kata-containers/runtime-rs
SRC_CANDIDATES=(
  "/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-qemu-runtime-rs.toml"
  "/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml"
  "/opt/kata/share/defaults/kata-containers/runtime-rs/configuration.toml"
  "/usr/share/defaults/kata-containers/runtime-rs/configuration.toml"
)

for src in "${SRC_CANDIDATES[@]}"; do
  if [[ -f "$src" ]]; then
    ln -sf "$src" /etc/kata-containers/runtime-rs/configuration.toml
    echo "Linked runtime-rs config -> $src" >&2
    break
  fi
done

if [[ ! -f /etc/kata-containers/runtime-rs/configuration.toml ]]; then
  echo "Warning: could not find a default runtime-rs configuration in known locations." >&2
  echo "Check /opt/kata/share/defaults/kata-containers/ and create: /etc/kata-containers/runtime-rs/configuration.toml" >&2
  exit 1
fi

echo "Kata assets installed. Restart containerd and test a kata container." >&2
echo "  sudo systemctl restart containerd" >&2
echo "  sudo nerdctl run --rm --runtime io.containerd.kata.v2 alpine:3.19 uname -a" >&2
