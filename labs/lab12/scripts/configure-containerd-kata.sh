#!/usr/bin/env bash
set -euo pipefail

# Add the Kata runtime to containerd config.
# Usage: sudo bash labs/lab12/scripts/configure-containerd-kata.sh

CONF="${CONF:-/etc/containerd/config.toml}"
TMP=$(mktemp)

backup() {
  if [ -f "$CONF" ]; then
    cp -a "$CONF" "${CONF}.$(date +%Y%m%d%H%M%S).bak"
  fi
}

ensure_default() {
  if [ ! -s "$CONF" ]; then
    mkdir -p "$(dirname "$CONF")"
    containerd config default > "$CONF"
  fi
}

insert_or_update_kata() {
  local header="[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]"
  local value="  runtime_type = 'io.containerd.kata.v2'"

  if grep -qF "$header" "$CONF"; then
    awk -v hdr="$header" -v val="$value" '
      BEGIN { inside=0 }
      {
        if ($0 == hdr) { inside=1; print $0; next }
        if (inside && $0 ~ /^\[/) { inside=0; print $0; next }
        if (inside && $0 ~ /^\s*runtime_type\s*=/) { print val; next }
        print $0
      }
    ' "$CONF" > "$TMP"
  else
    cp "$CONF" "$TMP"
    printf '
%s
%s
' "$header" "$value" >> "$TMP"
  fi
  install -m 0644 "$TMP" "$CONF"
}

backup
ensure_default
insert_or_update_kata
echo "Updated $CONF with Kata runtime. Restart containerd to apply." >&2
