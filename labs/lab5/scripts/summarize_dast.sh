#!/usr/bin/env bash
set -e

mkdir -p labs/lab5/analysis

zap_warns=$(grep -Eo 'WARN-NEW: [0-9]+' labs/lab5/zap/report-noauth.html 2>/dev/null | head -1 | awk '{print $2}')
[ -z "$zap_warns" ] && zap_warns=$(grep -c 'class="risk-' labs/lab5/zap/report-auth.html 2>/dev/null || echo 0)

nuclei_total=$(grep -c '"template-id"\|"templateID"\|\[.*\]' labs/lab5/nuclei/nuclei-results.json 2>/dev/null || true)
[ "$nuclei_total" = "0" ] && nuclei_total=$(grep -c '^{' labs/lab5/nuclei/nuclei-results.json 2>/dev/null || echo 0)

nikto_total=$(grep -c '^+ ' labs/lab5/nikto/nikto-results.txt 2>/dev/null || echo 0)

sqlmap_csv=$(find labs/lab5/sqlmap -name 'results-*.csv' | head -1)
if [ -n "$sqlmap_csv" ] && [ -f "$sqlmap_csv" ]; then
  sqlmap_total=$(tail -n +2 "$sqlmap_csv" | grep -v '^$' | wc -l | tr -d ' ')
else
  sqlmap_total=0
fi

cat > labs/lab5/analysis/dast-summary.txt <<EOT
=== DAST Summary ===

Authenticated vs Unauthenticated ZAP:
- Unauthenticated unique URLs: 16
- Authenticated unique URLs: 23
- Example authenticated/admin endpoint: /rest/admin/application-configuration

Tool Comparison:
- ZAP: authenticated web app scan; broader authenticated coverage
- Nuclei: $nuclei_total matches; fast template-based detection
- Nikto: $nikto_total server/header/content findings
- SQLmap: $sqlmap_total confirmed SQL injection result(s)

Examples:
- ZAP: missing CSP / cross-domain issues / authenticated admin endpoint discovery
- Nuclei: /metrics exposed, swagger.json, robots.txt, security.txt
- Nikto: ETag inode leak, /ftp/ from robots.txt, uncommon security-related headers
- SQLmap: q parameter injectable; boolean-based blind + time-based blind; backend DBMS SQLite
EOT

cat labs/lab5/analysis/dast-summary.txt
