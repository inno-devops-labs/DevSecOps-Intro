#!/usr/bin/env bash
set -euo pipefail

# configure-containerd-kata.sh
# Idempotently ensure containerd has the Kata runtime configured:
#   [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata]
#     runtime_type = "io.containerd.kata.v2"
#
# Usage:
#   sudo bash labs/lab12/scripts/configure-containerd-kata.sh

CONF_DEFAULT="/etc/containerd/config.toml"
# Allow override via $CONF or first CLI arg
CONF="${CONF:-${1:-$CONF_DEFAULT}}"
TMP=$(mktemp)

backup() {
  if [ -f "$CONF" ]; then
    cp -a "$CONF" "${CONF}.$(date +%Y%m%d%H%M%S).bak"
  fi
}

ensure_default() {
  if [ ! -s "$CONF" ]; then
    echo "Generating default containerd config at $CONF" >&2
    mkdir -p "$(dirname "$CONF")"
    containerd config default > "$CONF"
  fi
}

detect_header() {
  # Prefer modern CRI v1.runtime path if any related table exists; otherwise fallback to legacy grpc path.
  if grep -Eq "^\[plugins\.[\"']io\.containerd\.cri\.v1\.runtime[\"']([.].*)?\]" "$CONF"; then
    echo '[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata]'
  else
    echo '[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]'
  fi
}

insert_or_update_kata() {
  local header
  header=$(detect_header)
  local value='  runtime_type = "io.containerd.kata.v2"'

  # Process file: keep exactly one runtime_type inside the target kata table.
  # If table does not exist, append it once at EOF.
  awk -v hdr="$header" -v val="$value" '
    BEGIN { inside=0; seen=0; updated=0 }
    {
      if ($0 == hdr) {
        seen=1
        inside=1
        updated=0
        print $0
        next
      }
      if (inside) {
        if ($0 ~ /^\[/) {
          if (!updated) print val
          inside=0
          print $0
          next
        }
        if ($0 ~ /^[[:space:]]*runtime_type[[:space:]]*=[[:space:]]*/) {
          if (!updated) {
            print val
            updated=1
          }
          next
        }
        print $0
        next
      }
      print $0
    }
    END {
      if (inside && !updated) {
        print val
      }
      if (!seen) {
        print ""
        print hdr
        print val
      }
    }
  ' "$CONF" > "$TMP"

  install -m 0644 "$TMP" "$CONF"
}

main() {
  backup
  ensure_default
  insert_or_update_kata
  echo "Updated $CONF with Kata runtime: io.containerd.kata.v2" >&2
  echo "Restart containerd to apply: sudo systemctl restart containerd" >&2
}

main "$@"
