#!/bin/bash
echo "=== ZAP Authenticated vs Unauthenticated Comparison ==="
echo ""

# Count alerts in unauthenticated scan
if [ -f "labs/lab5/zap/zap-report-noauth.json" ]; then
  noauth_alerts=$(jq '.site[0].alerts | length' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "0")
  echo "Unauthenticated scan alerts: $noauth_alerts"
  echo "Unauthenticated alert breakdown:"
  jq -r '.site[0].alerts[] | "  [\(.riskdesc)] \(.alert)"' labs/lab5/zap/zap-report-noauth.json 2>/dev/null
else
  echo "Unauthenticated report not found"
fi

echo ""

# Count alerts in authenticated scan
if [ -f "labs/lab5/zap/report-auth.json" ]; then
  auth_alerts=$(jq '[.site[] | select(.["@host"] == "localhost") | .alerts[]] | length' labs/lab5/zap/report-auth.json 2>/dev/null || echo "0")
  echo "Authenticated scan alerts: $auth_alerts"
  echo "Authenticated alert breakdown:"
  jq -r '.site[] | select(.["@host"] == "localhost") | .alerts[] | "  [\(.riskdesc)] \(.alert)"' labs/lab5/zap/report-auth.json 2>/dev/null
else
  echo "Authenticated report not found"
fi

echo ""
echo "=== Summary ==="
echo "Unauthenticated: ${noauth_alerts:-0} alerts"
echo "Authenticated: ${auth_alerts:-0} alerts"
