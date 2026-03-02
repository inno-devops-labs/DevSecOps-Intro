#!/usr/bin/env bash
set -euo pipefail

echo "=== DAST Summary ==="
echo

if [[ -f labs/lab5/zap/report-auth.html ]]; then
  zap_med=$(grep -c 'class="risk-2"' labs/lab5/zap/report-auth.html || true)
  zap_high=$(grep -c 'class="risk-3"' labs/lab5/zap/report-auth.html || true)
  zap_low=$(grep -c 'class="risk-1"' labs/lab5/zap/report-auth.html || true)
  zap_info=$(grep -c 'class="risk-0"' labs/lab5/zap/report-auth.html || true)
  zap_total=$(( (zap_med / 2) + (zap_high / 2) + (zap_low / 2) + (zap_info / 2) ))
  echo "ZAP (auth): total alerts approx=$zap_total low=$((zap_low / 2)) medium=$((zap_med / 2)) high=$((zap_high / 2)) info=$((zap_info / 2))"
else
  echo "ZAP (auth): report-auth.html not found"
fi

if [[ -f labs/lab5/nuclei/nuclei-results.json ]]; then
  nuclei_total=$(wc -l < labs/lab5/nuclei/nuclei-results.json | tr -d ' ')
  nuclei_high=$(grep -ic '"severity":"high"' labs/lab5/nuclei/nuclei-results.json || true)
  nuclei_medium=$(grep -ic '"severity":"medium"' labs/lab5/nuclei/nuclei-results.json || true)
  nuclei_low=$(grep -ic '"severity":"low"' labs/lab5/nuclei/nuclei-results.json || true)
  nuclei_info=$(grep -ic '"severity":"info"' labs/lab5/nuclei/nuclei-results.json || true)
  nuclei_critical=$(grep -ic '"severity":"critical"' labs/lab5/nuclei/nuclei-results.json || true)
  echo "Nuclei: total=$nuclei_total critical=$nuclei_critical high=$nuclei_high medium=$nuclei_medium low=$nuclei_low info=$nuclei_info"
else
  echo "Nuclei: nuclei-results.json not found"
fi

if [[ -f labs/lab5/nikto/nikto-results.txt ]]; then
  nikto_total=$(grep -c '^+ ' labs/lab5/nikto/nikto-results.txt || true)
  echo "Nikto: findings(lines starting with '+ ')=$nikto_total"
else
  echo "Nikto: nikto-results.txt not found"
fi

sqlmap_csv=$(find labs/lab5/sqlmap -name "results-*.csv" | head -1 || true)
if [[ -n "${sqlmap_csv}" && -f "${sqlmap_csv}" ]]; then
  sqlmap_total=$(tail -n +2 "$sqlmap_csv" | grep -v '^$' | wc -l | tr -d ' ')
  echo "SQLmap: injected endpoints in ${sqlmap_csv} => $sqlmap_total"
else
  echo "SQLmap: results CSV not found"
fi
