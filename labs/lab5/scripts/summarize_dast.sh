#!/bin/bash
# Summarize DAST results from all tools

echo "=== DAST Multi-Tool Results Summary ==="
echo ""

# ZAP Results
echo "--- OWASP ZAP (Authenticated) ---"
if [ -f "labs/lab5/zap/zap-report-auth.json" ]; then
  zap_total=$(jq '.site[0].alerts | length' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
  zap_high=$(jq '[.site[0].alerts[] | select(.riskcode == "3")] | length' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
  zap_med=$(jq '[.site[0].alerts[] | select(.riskcode == "2")] | length' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
  zap_low=$(jq '[.site[0].alerts[] | select(.riskcode == "1")] | length' labs/lab5/zap/zap-report-auth.json 2>/dev/null || echo "0")
  echo "  Total: $zap_total | High: $zap_high | Medium: $zap_med | Low: $zap_low"
else
  echo "  Report not found"
fi
echo ""

# Nuclei Results
echo "--- Nuclei ---"
if [ -f "labs/lab5/nuclei/nuclei-results.json" ]; then
  nuclei_total=$(wc -l < labs/lab5/nuclei/nuclei-results.json)
  nuclei_crit=$(grep -c '"critical"' labs/lab5/nuclei/nuclei-results.json 2>/dev/null || echo "0")
  nuclei_high=$(grep -c '"high"' labs/lab5/nuclei/nuclei-results.json 2>/dev/null || echo "0")
  nuclei_med=$(grep -c '"medium"' labs/lab5/nuclei/nuclei-results.json 2>/dev/null || echo "0")
  nuclei_low=$(grep -c '"low"' labs/lab5/nuclei/nuclei-results.json 2>/dev/null || echo "0")
  nuclei_info=$(grep -c '"info"' labs/lab5/nuclei/nuclei-results.json 2>/dev/null || echo "0")
  echo "  Total: $nuclei_total | Critical: $nuclei_crit | High: $nuclei_high | Medium: $nuclei_med | Low: $nuclei_low | Info: $nuclei_info"
else
  echo "  Report not found"
fi
echo ""

# Nikto Results
echo "--- Nikto ---"
if [ -f "labs/lab5/nikto/nikto-results.txt" ]; then
  nikto_total=$(grep -c '+ ' labs/lab5/nikto/nikto-results.txt 2>/dev/null || echo "0")
  echo "  Total findings: $nikto_total"
else
  echo "  Report not found"
fi
echo ""

# SQLmap Results
echo "--- SQLmap ---"
sqlmap_csv=$(find labs/lab5/sqlmap -name "results-*.csv" 2>/dev/null | head -1)
if [ -f "$sqlmap_csv" ]; then
  sqlmap_count=$(tail -n +2 "$sqlmap_csv" | grep -v '^$' | wc -l)
  echo "  SQL Injection vulnerabilities found: $sqlmap_count"
else
  echo "  Checking for log files..."
  sqlmap_log=$(find labs/lab5/sqlmap -name "log" 2>/dev/null | head -1)
  if [ -f "$sqlmap_log" ]; then
    sqlmap_injectable=$(grep -c "injectable" "$sqlmap_log" 2>/dev/null || echo "0")
    echo "  Injectable parameters found: $sqlmap_injectable"
  else
    echo "  Report not found"
  fi
fi
echo ""
echo "=== End of Summary ==="
