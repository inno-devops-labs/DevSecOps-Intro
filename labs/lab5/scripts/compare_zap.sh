#!/bin/bash

echo "=== ZAP Authenticated vs Unauthenticated Comparison ==="
echo ""

# Count URLs discovered
noauth_urls=$(grep -o '"url":' labs/lab5/zap/zap-report-noauth.json 2>/dev/null | wc -l | tr -d ' ')
auth_urls=$(grep -o '"url":' labs/lab5/zap/zap-report-auth.json 2>/dev/null | wc -l | tr -d ' ')

echo "URLs Discovered:"
echo "  Unauthenticated scan: $noauth_urls URLs"
echo "  Authenticated scan: $auth_urls URLs"
echo "  Difference: $((auth_urls - noauth_urls)) additional URLs"
echo ""

# Count alerts by severity
echo "Alerts by Severity:"
echo ""
echo "Unauthenticated Scan:"
noauth_high=$(grep -c '"risk":"High"' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "0")
noauth_med=$(grep -c '"risk":"Medium"' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "0")
noauth_low=$(grep -c '"risk":"Low"' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "0")
noauth_info=$(grep -c '"risk":"Informational"' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "0")
echo "  High: $noauth_high"
echo "  Medium: $noauth_med"
echo "  Low: $noauth_low"
echo "  Informational: $noauth_info"
echo ""

echo "Authenticated Scan:"
auth_high=$(grep -c '"risk":"High"' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
auth_med=$(grep -c '"risk":"Medium"' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
auth_low=$(grep -c '"risk":"Low"' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
auth_info=$(grep -c '"risk":"Informational"' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
echo "  High: $auth_high"
echo "  Medium: $auth_med"
echo "  Low: $auth_low"
echo "  Informational: $auth_info"
echo ""

# Show admin endpoints discovered
echo "Sample Admin/Authenticated Endpoints Discovered:"
grep -o '"url":"[^"]*admin[^"]*"' labs/lab5/zap/zap-report-auth.json 2>/dev/null | head -5 | sed 's/"url":"//g' | sed 's/"//g' || echo "  (checking...)"
