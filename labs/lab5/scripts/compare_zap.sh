#!/bin/bash
# Compare ZAP Authenticated vs Unauthenticated scan results

echo "=== ZAP Scan Comparison: Authenticated vs Unauthenticated ==="
echo ""

# Count alerts in unauthenticated scan
if [ -f "labs/lab5/zap/zap-report-noauth.json" ]; then
  noauth_alerts=$(jq '.site[0].alerts | length' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "N/A")
  noauth_high=$(jq '[.site[0].alerts[] | select(.riskcode == "3")] | length' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "0")
  noauth_med=$(jq '[.site[0].alerts[] | select(.riskcode == "2")] | length' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "0")
  noauth_low=$(jq '[.site[0].alerts[] | select(.riskcode == "1")] | length' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "0")
  noauth_info=$(jq '[.site[0].alerts[] | select(.riskcode == "0")] | length' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "0")
else
  echo "WARNING: Unauthenticated report not found"
  noauth_alerts="N/A"
fi

# Count alerts in authenticated scan
if [ -f "labs/lab5/zap/zap-report-auth.json" ]; then
  auth_alerts=$(jq '.site[0].alerts | length' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "N/A")
  auth_high=$(jq '[.site[0].alerts[] | select(.riskcode == "3")] | length' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
  auth_med=$(jq '[.site[0].alerts[] | select(.riskcode == "2")] | length' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
  auth_low=$(jq '[.site[0].alerts[] | select(.riskcode == "1")] | length' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
  auth_info=$(jq '[.site[0].alerts[] | select(.riskcode == "0")] | length' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
else
  echo "WARNING: Authenticated report not found"
  auth_alerts="N/A"
fi

echo "Metric                | Unauthenticated | Authenticated"
echo "----------------------|-----------------|---------------"
echo "Total Alerts          | $noauth_alerts              | $auth_alerts"
echo "High Risk             | $noauth_high                | $auth_high"
echo "Medium Risk           | $noauth_med                | $auth_med"
echo "Low Risk              | $noauth_low                | $auth_low"
echo "Informational         | $noauth_info               | $auth_info"
echo ""
echo "=== End of Comparison ==="
