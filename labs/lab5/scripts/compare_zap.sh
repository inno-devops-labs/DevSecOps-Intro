#!/bin/bash
# Compares authenticated vs unauthenticated ZAP scan results using actual report data

set -e

NOAUTH="labs/lab5/zap/zap-report-noauth.json"
AUTH="labs/lab5/zap/zap-report-auth.json"
OUT="labs/lab5/analysis/zap-comparison.txt"
mkdir -p labs/lab5/analysis

parse_report() {
  local file="$1"
  local label="$2"

  if [ ! -f "$file" ]; then
    echo "$label: report not found ($file)"
    return
  fi

  echo "$label:"
  python3 -c "
import json, sys
with open('$file') as f:
    data = json.load(f)

sites = data.get('site', [])
total_alerts = 0
by_risk = {'3': 0, '2': 0, '1': 0, '0': 0}
risk_names = {'3': 'High', '2': 'Medium', '1': 'Low', '0': 'Info'}

for site in sites:
    if 'localhost:3000' not in site.get('@name', ''):
        continue
    for alert in site.get('alerts', []):
        risk = alert.get('riskcode', '0')
        by_risk[risk] = by_risk.get(risk, 0) + 1
        total_alerts += 1

print(f'  Total alerts: {total_alerts}')
for code in ['3','2','1','0']:
    print(f'  {risk_names[code]}: {by_risk[code]}')

# count unique URLs scanned
urls = set()
for site in sites:
    if 'localhost:3000' not in site.get('@name', ''):
        continue
    for alert in site.get('alerts', []):
        for inst in alert.get('instances', []):
            urls.add(inst.get('uri', ''))
print(f'  Unique URLs with findings: {len(urls)}')
"
}

{
  echo "ZAP Scan Comparison: Authenticated vs Unauthenticated"
  echo "Generated: $(date)"
  echo ""
  parse_report "$NOAUTH" "Unauthenticated Scan"
  echo ""
  parse_report "$AUTH" "Authenticated Scan"
} | tee "$OUT"

echo ""
echo "Saved to: $OUT"
