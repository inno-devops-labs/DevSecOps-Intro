#!/usr/bin/env bash
set -euo pipefail

NOAUTH_JSON="labs/lab5/zap/zap-report-noauth.json"
AUTH_JSON="labs/lab5/zap/zap-report-auth.json"
NOAUTH_LOG="labs/lab5/zap/zap-noauth-scan.log"
AUTH_LOG="labs/lab5/zap/zap-auth-scan.log"
OUT_FILE="labs/lab5/analysis/zap-comparison.txt"

extract_number_from_log() {
  local file="$1"
  local pattern="$2"
  local field="$3"
  if [[ -f "$file" ]]; then
    awk -v pat="$pattern" -v idx="$field" '
      $0 ~ pat {
        value=$idx
        gsub(/[^0-9]/, "", value)
        print value
        exit
      }
    ' "$file"
  fi
}

count_risk_alerts() {
  local file="$1"
  local risk="$2"
  if [[ -f "$file" ]]; then
    jq "[.site[]?.alerts[]? | select(((.\"@riskcode\" // .riskcode // \"\") == \"$risk\"))] | length" "$file" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

count_unique_uris() {
  local file="$1"
  if [[ -f "$file" ]]; then
    jq "[.site[]?.alerts[]?.instances[]?.uri | select(. != null)] | unique | length" "$file" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

noauth_discovered="$(extract_number_from_log "$NOAUTH_LOG" "Total of .* URLs" 3 || true)"
auth_spider="$(extract_number_from_log "$AUTH_LOG" "Job spider found .* URLs" 4 || true)"
auth_ajax="$(extract_number_from_log "$AUTH_LOG" "Job spiderAjax found .* URLs" 4 || true)"

if [[ -z "${noauth_discovered:-}" ]]; then
  noauth_discovered="$(count_unique_uris "$NOAUTH_JSON")"
fi

if [[ -z "${auth_spider:-}" ]]; then
  auth_spider="0"
fi

if [[ -z "${auth_ajax:-}" ]]; then
  auth_ajax="$(count_unique_uris "$AUTH_JSON")"
fi

if [[ "$auth_spider" =~ ^[0-9]+$ && "$auth_ajax" =~ ^[0-9]+$ ]]; then
  auth_total_urls=$((auth_spider + auth_ajax))
else
  auth_total_urls="$(count_unique_uris "$AUTH_JSON")"
fi

noauth_high="$(count_risk_alerts "$NOAUTH_JSON" "3")"
noauth_medium="$(count_risk_alerts "$NOAUTH_JSON" "2")"
noauth_low="$(count_risk_alerts "$NOAUTH_JSON" "1")"
noauth_info="$(count_risk_alerts "$NOAUTH_JSON" "0")"

auth_high="$(count_risk_alerts "$AUTH_JSON" "3")"
auth_medium="$(count_risk_alerts "$AUTH_JSON" "2")"
auth_low="$(count_risk_alerts "$AUTH_JSON" "1")"
auth_info="$(count_risk_alerts "$AUTH_JSON" "0")"

coverage_growth="n/a"
if [[ "$noauth_discovered" =~ ^[0-9]+$ && "$auth_total_urls" =~ ^[0-9]+$ && "$noauth_discovered" -gt 0 ]]; then
  coverage_growth="$(( (auth_total_urls - noauth_discovered) * 100 / noauth_discovered ))%"
fi

{
  echo "=== ZAP Auth vs Unauth Comparison ==="
  echo
  echo "URL discovery:"
  echo "  - Unauthenticated: $noauth_discovered URLs"
  echo "  - Authenticated:   $auth_total_urls URLs (spider=$auth_spider, ajax=$auth_ajax)"
  echo "  - Coverage growth: $coverage_growth"
  echo
  echo "Alert counts by risk:"
  echo "  - Unauthenticated: High=$noauth_high, Medium=$noauth_medium, Low=$noauth_low, Info=$noauth_info"
  echo "  - Authenticated:   High=$auth_high, Medium=$auth_medium, Low=$auth_low, Info=$auth_info"
  echo
  echo "Authenticated admin endpoint examples:"
  if [[ -f "$AUTH_JSON" ]]; then
    jq -r "[.site[]?.alerts[]?.instances[]?.uri | select(. != null)] | unique[]" "$AUTH_JSON" \
      | awk '/\/rest\/admin\// {print "  - " $0; shown++; if (shown == 8) exit}'
  fi
} > "$OUT_FILE"

cat "$OUT_FILE"
