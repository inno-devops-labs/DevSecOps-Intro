#!/usr/bin/env bash
set -e

echo "=== ZAP Comparison ===" > labs/lab5/analysis/zap-comparison.txt
echo "" >> labs/lab5/analysis/zap-comparison.txt

noauth_urls=$(grep -oE 'http://localhost:3000[^"< ]*' labs/lab5/zap/report-noauth.html 2>/dev/null | sort -u | wc -l | tr -d ' ')
auth_urls=$(grep -oE 'http://localhost:3000[^"< ]*' labs/lab5/zap/report-auth.html 2>/dev/null | sort -u | wc -l | tr -d ' ')

echo "Unauthenticated scan unique URLs: $noauth_urls" >> labs/lab5/analysis/zap-comparison.txt
echo "Authenticated scan unique URLs: $auth_urls" >> labs/lab5/analysis/zap-comparison.txt
echo "" >> labs/lab5/analysis/zap-comparison.txt

echo "Admin endpoints seen in authenticated report:" >> labs/lab5/analysis/zap-comparison.txt
grep -oE 'http://localhost:3000/rest/admin[^"< ]*' labs/lab5/zap/report-auth.html 2>/dev/null | sort -u | head -20 >> labs/lab5/analysis/zap-comparison.txt || true

echo "" >> labs/lab5/analysis/zap-comparison.txt
echo "Sample basket/profile/account endpoints from authenticated report:" >> labs/lab5/analysis/zap-comparison.txt
grep -oE 'http://localhost:3000/rest/(basket|user|address|payment)[^"< ]*' labs/lab5/zap/report-auth.html 2>/dev/null | sort -u | head -20 >> labs/lab5/analysis/zap-comparison.txt || true

cat labs/lab5/analysis/zap-comparison.txt
