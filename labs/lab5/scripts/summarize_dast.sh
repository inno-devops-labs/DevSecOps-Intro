#!/bin/bash
# Summarizes findings from all DAST tools using actual scan output files

set -e

OUT="labs/lab5/analysis/dast-summary.txt"
mkdir -p labs/lab5/analysis

{
  echo "DAST Multi-Tool Results Summary"
  echo "Generated: $(date)"
  echo ""

  # ZAP
  echo "=== ZAP ==="
  ZAP_JSON="labs/lab5/zap/zap-report-auth.json"
  if [ -f "$ZAP_JSON" ]; then
    python3 -c "
import json
with open('$ZAP_JSON') as f:
    data = json.load(f)
total = 0
for site in data.get('site', []):
    if 'localhost:3000' not in site.get('@name', ''):
        continue
    alerts = site.get('alerts', [])
    total = len(alerts)
    for a in sorted(alerts, key=lambda x: x.get('riskcode','0'), reverse=True)[:10]:
        risk = {'3':'HIGH','2':'MED','1':'LOW','0':'INFO'}.get(a.get('riskcode','0'),'?')
        print(f'  [{risk}] {a[\"name\"]}')
print(f'Total: {total} alert types')
"
  else
    echo "  Not yet generated (run authenticated ZAP scan first)"
  fi
  echo ""

  # Nuclei
  echo "=== Nuclei ==="
  NUCLEI="labs/lab5/nuclei/nuclei-results.json"
  if [ -f "$NUCLEI" ]; then
    count=$(wc -l < "$NUCLEI")
    echo "  Findings: $count"
    head -5 "$NUCLEI" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        sev = d.get('info',{}).get('severity','?').upper()
        name = d.get('info',{}).get('name','?')
        print(f'  [{sev}] {name}')
    except: pass
" 2>/dev/null
  else
    echo "  Not yet generated (run Nuclei scan first)"
  fi
  echo ""

  # Nikto
  echo "=== Nikto ==="
  NIKTO="labs/lab5/nikto/nikto-results.txt"
  if [ -f "$NIKTO" ]; then
    count=$(grep -c '^+ ' "$NIKTO" 2>/dev/null || echo "0")
    echo "  Findings: $count"
    grep '^+ ' "$NIKTO" | grep -v "^+ Target\|^+ Start\|^+ End\|^+ SSL\|^+ Server:" | head -5 | sed 's/^/  /'
  else
    echo "  Not yet generated (run Nikto scan first)"
  fi
  echo ""

  # SQLmap
  echo "=== SQLmap ==="
  SQLMAP_LOG=$(find labs/lab5/sqlmap -name "log" -type f 2>/dev/null | head -1)
  if [ -n "$SQLMAP_LOG" ] && [ -f "$SQLMAP_LOG" ]; then
    injection_count=$(grep -c "^Parameter:" "$SQLMAP_LOG" 2>/dev/null || echo "0")
    echo "  Injection points: $injection_count"
    grep "^Parameter:\|Type:\|Title:\|back-end DBMS:" "$SQLMAP_LOG" | head -10 | sed 's/^/  /'
  else
    echo "  Not yet generated (run SQLmap scans first)"
  fi

} | tee "$OUT"

echo ""
echo "Saved to: $OUT"
