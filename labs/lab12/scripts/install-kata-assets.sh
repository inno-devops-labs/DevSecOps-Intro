#!/usr/bin/env bash
set -euo pipefail

ver=${1:-}
a=$(uname -m)
case "$a" in
  x86_64) a=amd64 ;;
  aarch64|arm64) a=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [[ -n "$ver" ]]; then
  k="${ver#v}"
else
  k=$(curl -fsSL https://api.github.com/repos/kata-containers/kata-containers/releases/latest | jq -r .tag_name)
  k="${k#v}"
fi

u="https://github.com/kata-containers/kata-containers/releases/download/${k}/kata-static-${k}-${a}.tar.zst"

tmp=$(mktemp --suffix=.tar.zst)
curl -fL -o "$tmp" "$u"

if command -v zstd >/dev/null 2>&1; then
  zstd -d -c "$tmp" | tar -xf - -C /
elif command -v unzstd >/dev/null 2>&1; then
  unzstd -c "$tmp" | tar -xf - -C /
elif tar --help 2>/dev/null | grep -q -- '--zstd'; then
  tar --zstd -xf "$tmp" -C /
else
  echo "zstd support missing" >&2
  exit 1
fi
rm -f "$tmp"

sudo mkdir -p /etc/kata-containers/runtime-rs
c=(
  "/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml"
  "/opt/kata/share/defaults/kata-containers/configuration-dragonball.toml"
  "/opt/kata/share/defaults/kata-containers/runtime-rs/configuration.toml"
  "/usr/share/defaults/kata-containers/runtime-rs/configuration.toml"
)

for s in "${c[@]}"; do
  if [[ -f "$s" ]]; then
    ln -sf "$s" /etc/kata-containers/runtime-rs/configuration.toml
    break
  fi
done

if [[ ! -f /etc/kata-containers/runtime-rs/configuration.toml ]]; then
  echo "runtime-rs configuration missing" >&2
  exit 1
fi
