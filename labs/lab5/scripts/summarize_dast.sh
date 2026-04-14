#!/bin/bash
echo "=== DAST Tool Results Summary ==="
echo ""

# ZAP Results
echo "--- OWASP ZAP (Authenticated) ---"
if [ -f "labs/lab5/zap/report-auth.json" ]; then
  jq -r '.site[] | select(.["@host"] == "localhost") | .alerts[] | "  [\(.riskdesc)] \(.alert) (instances: \(.instances | length))"' labs/lab5/zap/report-auth.json 2>/dev/null
  zap_count=$(jq '[.site[] | select(.["@host"] == "localhost") | .alerts[]] | length' labs/lab5/zap/report-auth.json 2>/dev/null)
  echo "  Total: $zap_count alert types"
else
  echo "  No results found"
fi

echo ""
echo "--- Nuclei ---"
if [ -f "labs/lab5/nuclei/nuclei-results.json" ]; then
  nuclei_count=$(wc -l < labs/lab5/nuclei/nuclei-results.json)
  echo "  Total findings: $nuclei_count"
  cat labs/lab5/nuclei/nuclei-results.json | while IFS= read -r line; do
    name=$(echo "$line" | jq -r '.info.name // "unknown"' 2>/dev/null)
    severity=$(echo "$line" | jq -r '.info.severity // "unknown"' 2>/dev/null)
    echo "  [$severity] $name"
  done
else
  echo "  No results found"
fi

echo ""
echo "--- Nikto ---"
if [ -f "labs/lab5/nikto/nikto-results.txt" ]; then
  nikto_count=$(grep -c '+ ' labs/lab5/nikto/nikto-results.txt 2>/dev/null || echo '0')
  echo "  Total findings: $nikto_count"
  grep '+ ' labs/lab5/nikto/nikto-results.txt | head -20
else
  echo "  No results found"
fi

echo ""
echo "--- SQLmap ---"
sqlmap_log=$(find labs/lab5/sqlmap -name "log" -type f 2>/dev/null | head -1)
if [ -n "$sqlmap_log" ]; then
  echo "  SQLmap findings:"
  grep -i "injectable\|vulnerable\|payload\|parameter.*is\|Type:" "$sqlmap_log" | head -20
else
  echo "  No results found"
fi

# Check for dumped data
sqlmap_dump=$(find labs/lab5/sqlmap -name "*.csv" -type f 2>/dev/null | head -1)
if [ -n "$sqlmap_dump" ]; then
  echo "  Dumped data files:"
  find labs/lab5/sqlmap -name "*.csv" -type f 2>/dev/null
fi
