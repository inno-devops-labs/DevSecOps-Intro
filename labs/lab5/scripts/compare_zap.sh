#!/usr/bin/env bash
set -euo pipefail

base_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
zap_dir="$base_dir/zap"

noauth_log="$zap_dir/zap-noauth.log"
auth_log="$zap_dir/zap-auth.log"
noauth_json="$zap_dir/zap-report-noauth.json"
auth_html="$zap_dir/report-auth.html"

extract_last_number() {
  local pattern="$1"
  local file="$2"
  local value
  value="$(grep -Eo "$pattern" "$file" 2>/dev/null | awk '{print $(NF-1)}' | tail -1 || true)"
  printf '%s' "${value:-0}"
}

extract_json_site_count() {
  local file="$1"
  if command -v jq >/dev/null 2>&1 && [ -f "$file" ]; then
    jq '[.site[]?.alerts[]?.instances[]?.uri] | map(select(. != null)) | unique | length' "$file" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

noauth_urls=0
if [ -f "$noauth_log" ]; then
  noauth_urls="$(extract_last_number 'Total of [0-9]+ URLs' "$noauth_log")"
fi
if [ "$noauth_urls" = "0" ]; then
  noauth_urls="$(extract_json_site_count "$noauth_json")"
fi

auth_spider_urls=0
auth_ajax_urls=0
if [ -f "$auth_log" ]; then
  auth_spider_urls="$(extract_last_number 'Job spider found [0-9]+ URLs' "$auth_log")"
  auth_ajax_urls="$(extract_last_number 'Job spiderAjax found [0-9]+ URLs' "$auth_log")"
fi

auth_urls="$auth_ajax_urls"
if [ "$auth_urls" = "0" ]; then
  auth_urls="$auth_spider_urls"
fi

admin_endpoints_file="$zap_dir/admin-endpoints.txt"
if [ -f "$auth_html" ]; then
  grep -Eo 'https?://[^"<>[:space:]]+/rest/admin/[^"<>[:space:]]*' "$auth_html" \
    | sort -u > "$admin_endpoints_file" || true
else
  : > "$admin_endpoints_file"
fi
admin_count="$(wc -l < "$admin_endpoints_file" | tr -d ' ')"

echo "=== ZAP Auth vs NoAuth Comparison ==="
echo "No-auth URL count: ${noauth_urls}"
echo "Auth spider URL count: ${auth_spider_urls}"
echo "Auth AJAX spider URL count: ${auth_ajax_urls}"
echo "Auth effective URL count: ${auth_urls}"
echo "Admin/auth-only endpoints found: ${admin_count}"

if [ "$noauth_urls" -gt 0 ] && [ "$auth_urls" -gt 0 ]; then
  delta=$((auth_urls - noauth_urls))
  pct=$((delta * 100 / noauth_urls))
  echo "Delta: ${delta} URLs (${pct}% vs unauthenticated)"
else
  echo "Delta: not available"
fi

echo
echo "Sample admin endpoints:"
if [ "$admin_count" -gt 0 ]; then
  sed -n '1,10p' "$admin_endpoints_file"
else
  echo "No /rest/admin/ endpoints were extracted."
  echo "If auth scan ran successfully, inspect $auth_log and $auth_html manually."
fi
