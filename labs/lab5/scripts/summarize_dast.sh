#!/usr/bin/env bash
# Summarize DAST results from ZAP, Nuclei, Nikto, SQLmap
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB5_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== DAST Tools Summary ==="
echo ""

# ZAP
if [[ -f "$LAB5_DIR/zap/report-noauth.html" ]]; then
  zap_med=$(grep -c 'class="risk-2"' "$LAB5_DIR/zap/report-noauth.html" 2>/dev/null || echo 0)
  zap_high=$(grep -c 'class="risk-3"' "$LAB5_DIR/zap/report-noauth.html" 2>/dev/null || echo 0)
  echo "ZAP (noauth): Medium=$zap_med High=$zap_high"
fi
if [[ -f "$LAB5_DIR/report-auth.html" ]]; then
  zap_med_a=$(grep -c 'class="risk-2"' "$LAB5_DIR/report-auth.html" 2>/dev/null || echo 0)
  zap_high_a=$(grep -c 'class="risk-3"' "$LAB5_DIR/report-auth.html" 2>/dev/null || echo 0)
  echo "ZAP (auth):   Medium=$zap_med_a High=$zap_high_a"
fi
echo ""

# Nuclei
if [[ -f "$LAB5_DIR/nuclei/nuclei-results.json" ]]; then
  nuclei_count=$(wc -l < "$LAB5_DIR/nuclei/nuclei-results.json" 2>/dev/null || echo 0)
  echo "Nuclei: $nuclei_count template matches (JSONL lines)"
else
  echo "Nuclei: results file not found"
fi
echo ""

# Nikto
if [[ -f "$LAB5_DIR/nikto/nikto-results.txt" ]]; then
  nikto_count=$(grep -c '+ ' "$LAB5_DIR/nikto/nikto-results.txt" 2>/dev/null || echo 0)
  echo "Nikto: $nikto_count findings (lines with '+ ')"
else
  echo "Nikto: results file not found"
fi
echo ""

# SQLmap
sqlmap_csv=$(find "$LAB5_DIR/sqlmap" -name "*.csv" 2>/dev/null | head -1)
if [[ -n "$sqlmap_csv" && -f "$sqlmap_csv" ]]; then
  sqlmap_count=$(tail -n +2 "$sqlmap_csv" 2>/dev/null | grep -v '^$' | wc -l | tr -d ' ')
  echo "SQLmap: $sqlmap_count extracted records (e.g. from dump)"
else
  echo "SQLmap: no CSV results found"
fi

echo ""
echo "--- Done ---"
