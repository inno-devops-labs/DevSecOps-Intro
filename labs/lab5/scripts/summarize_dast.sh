#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LAB_DIR="$ROOT_DIR/labs/lab5"
OUT_FILE="$LAB_DIR/analysis/dast-summary.txt"

zap_auth_html="$LAB_DIR/zap/report-auth.html"
zap_auth_json="$LAB_DIR/zap/zap-report-auth.json"
nuclei_jsonl="$LAB_DIR/nuclei/nuclei-results.json"
nikto_txt="$LAB_DIR/nikto/nikto-results.txt"

zap_high=0
zap_medium=0
zap_low=0
zap_info=0
zap_total=0

if [[ -f "$zap_auth_json" ]]; then
  zap_high=$(jq '[.site[]?.alerts[]? | select(.riskcode=="3")] | length' "$zap_auth_json" 2>/dev/null || echo 0)
  zap_medium=$(jq '[.site[]?.alerts[]? | select(.riskcode=="2")] | length' "$zap_auth_json" 2>/dev/null || echo 0)
  zap_low=$(jq '[.site[]?.alerts[]? | select(.riskcode=="1")] | length' "$zap_auth_json" 2>/dev/null || echo 0)
  zap_info=$(jq '[.site[]?.alerts[]? | select(.riskcode=="0")] | length' "$zap_auth_json" 2>/dev/null || echo 0)
  zap_total=$((zap_high + zap_medium + zap_low + zap_info))
elif [[ -f "$zap_auth_html" ]]; then
  # fallback if JSON report was not generated
  zap_high=$(( ($(grep -c 'class="risk-3"' "$zap_auth_html" 2>/dev/null || echo 0)) / 2 ))
  zap_medium=$(( ($(grep -c 'class="risk-2"' "$zap_auth_html" 2>/dev/null || echo 0)) / 2 ))
  zap_low=$(( ($(grep -c 'class="risk-1"' "$zap_auth_html" 2>/dev/null || echo 0)) / 2 ))
  zap_info=$(( ($(grep -c 'class="risk-0"' "$zap_auth_html" 2>/dev/null || echo 0)) / 2 ))
  zap_total=$((zap_high + zap_medium + zap_low + zap_info))
fi

nuclei_count=0
nuclei_critical=0
nuclei_high=0
nuclei_medium=0
nuclei_low=0
nuclei_info=0
if [[ -f "$nuclei_jsonl" ]]; then
  nuclei_count=$(wc -l < "$nuclei_jsonl" | tr -d ' ')
  nuclei_critical=$(jq -r 'select(.info.severity=="critical") | 1' "$nuclei_jsonl" 2>/dev/null | wc -l | tr -d ' ')
  nuclei_high=$(jq -r 'select(.info.severity=="high") | 1' "$nuclei_jsonl" 2>/dev/null | wc -l | tr -d ' ')
  nuclei_medium=$(jq -r 'select(.info.severity=="medium") | 1' "$nuclei_jsonl" 2>/dev/null | wc -l | tr -d ' ')
  nuclei_low=$(jq -r 'select(.info.severity=="low") | 1' "$nuclei_jsonl" 2>/dev/null | wc -l | tr -d ' ')
  nuclei_info=$(jq -r 'select(.info.severity=="info") | 1' "$nuclei_jsonl" 2>/dev/null | wc -l | tr -d ' ')
fi

nikto_count=0
if [[ -f "$nikto_txt" ]]; then
  nikto_count=$(grep -c '^+ ' "$nikto_txt" 2>/dev/null || echo 0)
fi

sqlmap_csv="$(find "$LAB_DIR/sqlmap" -name 'results-*.csv' 2>/dev/null | head -n 1 || true)"
sqlmap_count=0
if [[ -n "$sqlmap_csv" && -f "$sqlmap_csv" ]]; then
  sqlmap_count=$(tail -n +2 "$sqlmap_csv" | grep -v '^$' | wc -l | tr -d ' ')
fi

mkdir -p "$(dirname "$OUT_FILE")"
{
  echo "=== DAST Summary ==="
  echo
  echo "ZAP (authenticated):"
  echo "- Total alerts: $zap_total"
  echo "- Severity breakdown: high=$zap_high, medium=$zap_medium, low=$zap_low, info=$zap_info"
  echo
  echo "Nuclei:"
  echo "- Total findings: $nuclei_count"
  echo "- Severity breakdown: critical=$nuclei_critical, high=$nuclei_high, medium=$nuclei_medium, low=$nuclei_low, info=$nuclei_info"
  echo
  echo "Nikto:"
  echo "- Total findings: $nikto_count"
  echo
  echo "SQLmap:"
  echo "- Confirmed SQLi findings: $sqlmap_count"
  echo
  echo "Combined DAST findings (raw sum): $((zap_total + nuclei_count + nikto_count + sqlmap_count))"
} > "$OUT_FILE"

cat "$OUT_FILE"