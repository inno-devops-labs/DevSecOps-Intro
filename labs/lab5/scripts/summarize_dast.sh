#!/usr/bin/env bash
set -euo pipefail

base_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
zap_dir="$base_dir/zap"
nuclei_file="$base_dir/nuclei/nuclei-results.json"
nikto_file="$base_dir/nikto/nikto-results.txt"
sqlmap_dir="$base_dir/sqlmap"
sqlmap_search_dir="$base_dir/sqlmap-search"
summary_file="$base_dir/analysis/dast-summary.txt"

count_zap_risk() {
  local risk_class="$1"
  local html="$2"
  if [ -f "$html" ]; then
    grep -A4 "<td class=\"${risk_class}\">" "$html" 2>/dev/null \
      | grep -Eo '<div>[0-9]+</div>' \
      | head -1 \
      | grep -Eo '[0-9]+' || echo 0
  else
    echo 0
  fi
}

zap_info="$(count_zap_risk risk-0 "$zap_dir/report-auth.html")"
zap_low="$(count_zap_risk risk-1 "$zap_dir/report-auth.html")"
zap_medium="$(count_zap_risk risk-2 "$zap_dir/report-auth.html")"
zap_high="$(count_zap_risk risk-3 "$zap_dir/report-auth.html")"
zap_total=$((zap_info + zap_low + zap_medium + zap_high))

nuclei_total=0
nuclei_info=0
nuclei_low=0
nuclei_medium=0
nuclei_high=0
nuclei_critical=0
if [ -f "$nuclei_file" ]; then
  nuclei_total="$(wc -l < "$nuclei_file" | tr -d ' ')"
  if command -v jq >/dev/null 2>&1; then
    nuclei_info="$(jq -r 'select(.info.severity == "info") | 1' "$nuclei_file" 2>/dev/null | wc -l | tr -d ' ')"
    nuclei_low="$(jq -r 'select(.info.severity == "low") | 1' "$nuclei_file" 2>/dev/null | wc -l | tr -d ' ')"
    nuclei_medium="$(jq -r 'select(.info.severity == "medium") | 1' "$nuclei_file" 2>/dev/null | wc -l | tr -d ' ')"
    nuclei_high="$(jq -r 'select(.info.severity == "high") | 1' "$nuclei_file" 2>/dev/null | wc -l | tr -d ' ')"
    nuclei_critical="$(jq -r 'select(.info.severity == "critical") | 1' "$nuclei_file" 2>/dev/null | wc -l | tr -d ' ')"
  fi
fi

nikto_total=0
if [ -f "$nikto_file" ]; then
  nikto_total="$(grep -Ec '^\+ (GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH) ' "$nikto_file" 2>/dev/null || echo 0)"
fi

sqlmap_search_targets=0
sqlmap_login_targets=0
sqlmap_login_dumps=0
sqlmap_search_csv="$(find "$sqlmap_search_dir" -maxdepth 1 -name 'results-*.csv' 2>/dev/null | head -1 || true)"
if [ -n "$sqlmap_search_csv" ] && [ -f "$sqlmap_search_csv" ]; then
  sqlmap_search_targets="$(tail -n +2 "$sqlmap_search_csv" | grep -vc '^$' || true)"
fi
if [ -f "$sqlmap_dir/localhost/log" ] && grep -q 'sqlmap identified the following injection point' "$sqlmap_dir/localhost/log"; then
  sqlmap_login_targets=1
fi
sqlmap_login_dumps="$(find "$sqlmap_dir" -path '*/dump/*' -name '*.csv' 2>/dev/null | wc -l | tr -d ' ')"
sqlmap_total=$((sqlmap_search_targets + sqlmap_login_targets))

{
  echo "=== DAST Summary ==="
  echo
  echo "| Tool | Findings | Severity Breakdown | Best Use Case |"
  echo "|---|---:|---|---|"
  echo "| ZAP (auth) | ${zap_total} | High=${zap_high}, Medium=${zap_medium}, Low=${zap_low}, Info=${zap_info} | Broad web app coverage, authenticated crawl, active testing |"
  echo "| Nuclei | ${nuclei_total} | Critical=${nuclei_critical}, High=${nuclei_high}, Medium=${nuclei_medium}, Low=${nuclei_low}, Info=${nuclei_info} | Fast template-based checks and known exposures |"
  echo "| Nikto | ${nikto_total} | Text report, no native severity split | Server misconfigurations and risky defaults |"
  echo "| SQLmap | ${sqlmap_total} | ${sqlmap_total} confirmed injection target(s); login run dumped ${sqlmap_login_dumps} SQLite tables | Deep SQL injection validation and database dumping |"
  echo
  echo "Example findings to mention:"
  echo "- ZAP: missing security headers, CSP/header issues, authenticated endpoint coverage."
  echo "- Nuclei: template matches for exposed files, missing hardening, known signatures."
  echo "- Nikto: server header disclosure, insecure defaults, missing headers."
  echo "- SQLmap: confirmed GET /search SQLi and POST /login SQLi, with SQLite fingerprinting and database dumping."
} | tee "$summary_file"
