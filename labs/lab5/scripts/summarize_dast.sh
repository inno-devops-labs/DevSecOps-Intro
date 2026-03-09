#!/bin/bash

echo "=== DAST Tools Comparison Summary ==="
echo ""

# ZAP
echo "1. OWASP ZAP (Authenticated):"
zap_total=$(grep -c '"risk":' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
zap_high=$(grep -c '"risk":"High"' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
zap_med=$(grep -c '"risk":"Medium"' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
echo "   Total findings: $zap_total"
echo "   High: $zap_high, Medium: $zap_med"
echo "   Best for: Comprehensive web app scanning with authentication"
echo ""

# Nuclei
echo "2. Nuclei:"
if [ -f "labs/lab5/nuclei/nuclei-results.json" ]; then
    nuclei_count=$(wc -l < labs/lab5/nuclei/nuclei-results.json 2>/dev/null | tr -d ' ')
    echo "   Total findings: $nuclei_count"
    echo "   Best for: Fast CVE detection with community templates"
else
    echo "   Status: Scan in progress or no results"
    echo "   Best for: Fast CVE detection with community templates"
fi
echo ""

# Nikto
echo "3. Nikto:"
nikto_count=$(grep -c '+ ' labs/lab5/nikto/nikto-results.txt 2>/dev/null || echo "0")
echo "   Total findings: $nikto_count"
echo "   Best for: Web server misconfiguration detection"
echo ""

# SQLmap
echo "4. SQLmap:"
sqlmap_csv=$(find labs/lab5/sqlmap -name "results-*.csv" 2>/dev/null | head -1)
if [ -f "$sqlmap_csv" ]; then
    sqlmap_vuln=$(tail -n +2 "$sqlmap_csv" | grep -v '^$' | wc -l | tr -d ' ')
    echo "   SQL injection vulnerabilities: $sqlmap_vuln"
    echo "   Best for: Deep SQL injection analysis and exploitation"
else
    echo "   Status: No results file found"
    echo "   Best for: Deep SQL injection analysis and exploitation"
fi
echo ""

echo "=== Key Insights ==="
echo "- ZAP provides comprehensive coverage with authentication support"
echo "- Nuclei excels at known CVE detection with minimal setup"
echo "- Nikto identifies server-level misconfigurations"
echo "- SQLmap specializes in SQL injection testing and exploitation"
