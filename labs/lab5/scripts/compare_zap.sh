#!/bin/bash
# Compare ZAP authenticated vs unauthenticated scan results

echo "=== ZAP Scan Comparison ==="
echo ""

# Count URLs discovered in unauthenticated scan
if [ -f "labs/lab5/zap/zap-report-noauth.json" ]; then
    noauth_urls=$(jq -r '.site[] | .alerts[] | .url' labs/lab5/zap/zap-report-noauth.json 2>/dev/null | sort -u | wc -l | tr -d ' ')
    echo "Unauthenticated scan URLs discovered: ${noauth_urls:-0}"
else
    echo "Unauthenticated scan report not found"
    noauth_urls=0
fi

# Count URLs discovered in authenticated scan
if [ -f "labs/lab5/zap/report-auth.html" ]; then
    # Extract URLs from HTML report (approximate count)
    auth_urls=$(grep -o 'http://localhost:3000[^"]*' labs/lab5/zap/report-auth.html 2>/dev/null | sort -u | wc -l | tr -d ' ')
    echo "Authenticated scan URLs discovered: ${auth_urls:-0}"
else
    echo "Authenticated scan report not found"
    auth_urls=0
fi

echo ""
echo "=== Key Differences ==="
echo ""

# Find admin endpoints in authenticated scan
if [ -f "labs/lab5/zap/report-auth.html" ]; then
    admin_endpoints=$(grep -o 'http://localhost:3000/rest/admin[^"]*' labs/lab5/zap/report-auth.html 2>/dev/null | sort -u | head -5)
    if [ -n "$admin_endpoints" ]; then
        echo "Admin endpoints discovered (authenticated scan):"
        echo "$admin_endpoints" | sed 's/^/  - /'
    fi
fi

echo ""
echo "=== Alert Comparison ==="
echo ""

# Count alerts in unauthenticated scan
if [ -f "labs/lab5/zap/zap-report-noauth.json" ]; then
    noauth_alerts=$(jq '[.site[] | .alerts[]] | length' labs/lab5/zap/zap-report-noauth.json 2>/dev/null || echo "0")
    echo "Unauthenticated scan alerts: $noauth_alerts"
fi

# Count alerts in authenticated scan (from HTML)
if [ -f "labs/lab5/zap/report-auth.html" ]; then
    auth_high=$(grep -c 'class="risk-3"' labs/lab5/zap/report-auth.html 2>/dev/null || echo "0")
    auth_med=$(grep -c 'class="risk-2"' labs/lab5/zap/report-auth.html 2>/dev/null || echo "0")
    auth_low=$(grep -c 'class="risk-1"' labs/lab5/zap/report-auth.html 2>/dev/null || echo "0")
    auth_info=$(grep -c 'class="risk-0"' labs/lab5/zap/report-auth.html 2>/dev/null || echo "0")
    echo "Authenticated scan alerts:"
    echo "  High: $auth_high"
    echo "  Medium: $auth_med"
    echo "  Low: $auth_low"
    echo "  Info: $auth_info"
fi
