#!/usr/bin/env bash
set -euo pipefail

# Install Kata Containers static assets under /opt/kata.
# Usage: sudo bash labs/lab12/scripts/install-kata-assets.sh [KATA_VER]

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

if command -v zstd >/dev/null 2>&1; then
  zstd -d -c "${TMP_TAR}" | tar -xf - -C /
elif command -v unzstd >/dev/null 2>&1; then
  unzstd -c "${TMP_TAR}" | tar -xf - -C /
elif tar --help 2>/dev/null | grep -q -- '--zstd'; then
  tar --zstd -xf "${TMP_TAR}" -C /
else
  echo "Missing zstd support. Install zstd and re-run." >&2
  exit 1
fi
rm -f "${TMP_TAR}"

echo "Kata assets installed. Restart containerd: sudo systemctl restart containerd" >&2
