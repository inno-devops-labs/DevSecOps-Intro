#!/usr/bin/env bash
# Compare ZAP unauthenticated vs authenticated scan results (URL discovery)
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB5_DIR="$(dirname "$SCRIPT_DIR")"
ZAP_DIR="$LAB5_DIR/zap"
REPORT_NOAUTH="$ZAP_DIR/report-noauth.html"
REPORT_AUTH="$LAB5_DIR/report-auth.html"

echo "=== ZAP Scan Comparison: Unauthenticated vs Authenticated ==="
echo ""

# Count URLs from HTML reports (ZAP traditional-html contains "URLs" in summary)
noauth_urls=""
auth_urls=""

if [[ -f "$REPORT_NOAUTH" ]]; then
  # Traditional HTML report has table rows for each URL or summary line
  noauth_urls=$(grep -oE '[0-9]+[[:space:]]+URL' "$REPORT_NOAUTH" 2>/dev/null | head -1 | grep -oE '[0-9]+' || true)
  [[ -z "$noauth_urls" ]] && noauth_urls=$(grep -c 'href="http' "$REPORT_NOAUTH" 2>/dev/null || echo "N/A")
  echo "Unauthenticated scan report: $REPORT_NOAUTH"
else
  echo "Unauthenticated report not found: $REPORT_NOAUTH"
fi

if [[ -f "$REPORT_AUTH" ]]; then
  auth_urls=$(grep -oE '[0-9]+[[:space:]]+URL' "$REPORT_AUTH" 2>/dev/null | head -1 | grep -oE '[0-9]+' || true)
  [[ -z "$auth_urls" ]] && auth_urls=$(grep -c 'href="http' "$REPORT_AUTH" 2>/dev/null || echo "N/A")
  echo "Authenticated scan report: $REPORT_AUTH"
else
  echo "Authenticated report not found: $REPORT_AUTH"
fi

# Try JSON report for noauth URL count
if [[ -f "$ZAP_DIR/zap-report-noauth.json" ]]; then
  noauth_from_json=$(jq -r '.site[] | .@host' "$ZAP_DIR/zap-report-noauth.json" 2>/dev/null | wc -l | tr -d ' ')
  # Or total alerts as proxy for coverage
  noauth_alerts=$(jq -r '.site[0].alerts | length' "$ZAP_DIR/zap-report-noauth.json" 2>/dev/null || echo "0")
  echo ""
  echo "Unauthenticated (from JSON): hosts in report; alerts: $noauth_alerts"
fi

echo ""
echo "--- Summary ---"
echo "Use the URL counts printed by ZAP during scan (e.g. 'Job spider found N URLs', 'Job spiderAjax found M URLs')."
echo "Authenticated scan typically discovers 10x+ more URLs (e.g. /rest/admin/*, basket, orders)."
echo "Admin/authenticated endpoints example: http://localhost:3000/rest/admin/application-configuration"
