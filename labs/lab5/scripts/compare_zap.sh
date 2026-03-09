#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ZAP_DIR="$ROOT_DIR/labs/lab5/zap"
OUT_FILE="$ROOT_DIR/labs/lab5/analysis/zap-comparison.txt"

NOAUTH_LOG="$ZAP_DIR/zap-noauth-scan.log"
AUTH_LOG="$ZAP_DIR/zap-auth-scan.log"
NOAUTH_HTML="$ZAP_DIR/report-noauth.html"
AUTH_HTML="$ZAP_DIR/report-auth.html"

extract_alerts() {
  local html_file="$1"
  local severity="$2"
  if [[ ! -f "$html_file" ]]; then
    echo 0
    return
  fi
  grep -c "class=\"risk-$severity\"" "$html_file" 2>/dev/null || true
}

extract_num() {
  local pattern="$1"
  local file="$2"
  if [[ ! -f "$file" ]]; then
    echo 0
    return
  fi
  grep -Eo "$pattern" "$file" | tail -n 1 | grep -Eo '[0-9]+' | tail -n 1 || echo 0
}

noauth_urls="$(extract_num 'Total of [0-9]+ URLs' "$NOAUTH_LOG")"
auth_spider_urls="$(extract_num 'Job spider found [0-9]+ URLs' "$AUTH_LOG")"
auth_ajax_urls="$(extract_num 'Job spiderAjax found [0-9]+ URLs' "$AUTH_LOG")"
auth_total_urls=$(( auth_spider_urls + auth_ajax_urls ))

noauth_high_raw="$(extract_alerts "$NOAUTH_HTML" 3)"
noauth_med_raw="$(extract_alerts "$NOAUTH_HTML" 2)"
auth_high_raw="$(extract_alerts "$AUTH_HTML" 3)"
auth_med_raw="$(extract_alerts "$AUTH_HTML" 2)"

# Risk values appear in multiple sections in the HTML report; divide by 2 for a practical estimate.
noauth_high=$(( noauth_high_raw / 2 ))
noauth_med=$(( noauth_med_raw / 2 ))
auth_high=$(( auth_high_raw / 2 ))
auth_med=$(( auth_med_raw / 2 ))

admin_examples="none found"
if [[ -f "$AUTH_HTML" ]]; then
  matches="$(grep -Eo 'http://localhost:3000/rest/admin/[^"< ]+' "$AUTH_HTML" | sort -u | head -n 5 || true)"
  if [[ -n "$matches" ]]; then
    admin_examples="$(echo "$matches" | paste -sd ', ' -)"
  fi
fi

mkdir -p "$(dirname "$OUT_FILE")"
{
  echo "=== ZAP Authenticated vs Unauthenticated Comparison ==="
  echo
  echo "URL Discovery:"
  echo "- Unauthenticated baseline URLs: $noauth_urls"
  echo "- Authenticated spider URLs: $auth_spider_urls"
  echo "- Authenticated AJAX spider URLs: $auth_ajax_urls"
  echo "- Authenticated combined discovery (spider + AJAX): $auth_total_urls"
  if [[ "$noauth_urls" -gt 0 ]]; then
    improvement=$(( (auth_total_urls * 100 / noauth_urls) - 100 ))
    echo "- Relative increase vs baseline: ${improvement}%"
  fi
  echo
  echo "Alert Snapshot (estimated unique alerts from HTML reports):"
  echo "- Unauthenticated: high=$noauth_high, medium=$noauth_med"
  echo "- Authenticated: high=$auth_high, medium=$auth_med"
  echo
  echo "Sample authenticated admin endpoints:"
  echo "- $admin_examples"
} > "$OUT_FILE"

cat "$OUT_FILE"