#!/bin/bash
# Summarize DAST results from all tools

echo "=== DAST Tool Results Summary ==="
echo ""

# ZAP Results
echo "--- ZAP (OWASP ZAP) ---"
if [ -f "labs/lab5/zap/report-auth.html" ]; then
    zap_high=$(grep -c 'class="risk-3"' labs/lab5/zap/report-auth.html 2>/dev/null || echo "0")
    zap_med=$(grep -c 'class="risk-2"' labs/lab5/zap/report-auth.html 2>/dev/null || echo "0")
    zap_low=$(grep -c 'class="risk-1"' labs/lab5/zap/report-auth.html 2>/dev/null || echo "0")
    zap_info=$(grep -c 'class="risk-0"' labs/lab5/zap/report-auth.html 2>/dev/null || echo "0")
    echo "Findings: High=$zap_high, Medium=$zap_med, Low=$zap_low, Info=$zap_info"
else
    echo "Report not found"
fi
echo ""

# Nuclei Results
echo "--- Nuclei ---"
if [ -f "labs/lab5/nuclei/nuclei-results.json" ]; then
    nuclei_count=$(wc -l < labs/lab5/nuclei/nuclei-results.json 2>/dev/null || echo "0")
    echo "Template matches: $nuclei_count"
    if [ "$nuclei_count" -gt 0 ]; then
        echo "Sample findings:"
        jq -r '.info.name + " - " + .info.severity' labs/lab5/nuclei/nuclei-results.json 2>/dev/null | head -5 | sed 's/^/  - /'
    fi
else
    echo "Results file not found"
fi
echo ""

# Nikto Results
echo "--- Nikto ---"
if [ -f "labs/lab5/nikto/nikto-results.txt" ]; then
    nikto_count=$(grep -c '+ ' labs/lab5/nikto/nikto-results.txt 2>/dev/null || echo "0")
    echo "Server issues found: $nikto_count"
    if [ "$nikto_count" -gt 0 ]; then
        echo "Sample findings:"
        grep '+ ' labs/lab5/nikto/nikto-results.txt 2>/dev/null | head -5 | sed 's/^/  - /'
    fi
else
    echo "Results file not found"
fi
echo ""

# SQLmap Results
echo "--- SQLmap ---"
sqlmap_csv=$(find labs/lab5/sqlmap -name "results-*.csv" 2>/dev/null | head -1)
if [ -n "$sqlmap_csv" ] && [ -f "$sqlmap_csv" ]; then
    sqlmap_count=$(tail -n +2 "$sqlmap_csv" 2>/dev/null | grep -v '^$' | wc -l | tr -d ' ')
    echo "SQL injection vulnerabilities: $sqlmap_count"
    if [ "$sqlmap_count" -gt 0 ]; then
        echo "Vulnerable endpoints:"
        tail -n +2 "$sqlmap_csv" 2>/dev/null | grep -v '^$' | head -5 | sed 's/^/  - /'
    fi
else
    echo "Results file not found"
fi
echo ""

echo "=== Summary ==="
echo "Use these numbers in your submission5.md comparison table"
