#!/usr/bin/env bash
set -euo pipefail

c="${CONF:-${1:-/etc/containerd/config.toml}}"
t="$(mktemp)"

if [[ -f "$c" ]]; then
  cp -a "$c" "${c}.$(date +%Y%m%d%H%M%S).bak"
fi

if [[ ! -s "$c" ]]; then
  mkdir -p "$(dirname "$c")"
  containerd config default > "$c"
fi

if grep -q "^\[plugins\.'io\.containerd\.cri\.v1\.runtime'\]" "$c"; then
  h="[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata]"
else
  h="[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.kata]"
fi
v="  runtime_type = 'io.containerd.kata.v2'"

awk -v hdr="$h" -v val="$v" '
  BEGIN { in=0; done=0 }
  {
    if ($0 == hdr) { print; in=1; next }
    if (in) {
      if ($0 ~ /^\[/) { if (!done) print val; in=0; print; next }
      if ($0 ~ /^\s*runtime_type\s*=\s*/) { print val; done=1; next }
      print; next
    }
    print
  }
  END { if (in && !done) print val }
' "$c" > "$t"

if ! grep -qF "$h" "$t"; then
  printf '\n%s\n%s\n' "$h" "$v" >> "$t"
fi

install -m 0644 "$t" "$c"
