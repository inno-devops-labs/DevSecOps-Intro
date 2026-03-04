#!/usr/bin/env bash
set -euo pipefail

NOAUTH_ZAP_JSON="labs/lab5/zap/zap-report-noauth.json"
AUTH_ZAP_JSON="labs/lab5/zap/zap-report-auth.json"
NUCLEI_JSONL="labs/lab5/nuclei/nuclei-results.json"
NIKTO_TXT="labs/lab5/nikto/nikto-results.txt"
OUT_FILE="labs/lab5/analysis/dast-summary.txt"

count_zap_risk() {
  local file="$1"
  local risk="$2"
  if [[ -f "$file" ]]; then
    jq "[.site[]?.alerts[]? | select(((.\"@riskcode\" // .riskcode // \"\") == \"$risk\"))] | length" "$file" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

count_zap_total() {
  local file="$1"
  if [[ -f "$file" ]]; then
    jq "[.site[]?.alerts[]?] | length" "$file" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

zap_noauth_total="$(count_zap_total "$NOAUTH_ZAP_JSON")"
zap_auth_total="$(count_zap_total "$AUTH_ZAP_JSON")"
zap_auth_high="$(count_zap_risk "$AUTH_ZAP_JSON" "3")"
zap_auth_medium="$(count_zap_risk "$AUTH_ZAP_JSON" "2")"
zap_auth_low="$(count_zap_risk "$AUTH_ZAP_JSON" "1")"
zap_auth_info="$(count_zap_risk "$AUTH_ZAP_JSON" "0")"

nuclei_total="0"
nuclei_critical="0"
nuclei_high="0"
nuclei_medium="0"
nuclei_low="0"
nuclei_info="0"
nuclei_unknown="0"

if [[ -f "$NUCLEI_JSONL" ]]; then
  nuclei_total="$(awk 'END { print NR+0 }' "$NUCLEI_JSONL")"
  while IFS='=' read -r sev count; do
    case "$sev" in
      critical) nuclei_critical="$count" ;;
      high) nuclei_high="$count" ;;
      medium) nuclei_medium="$count" ;;
      low) nuclei_low="$count" ;;
      info) nuclei_info="$count" ;;
      *) nuclei_unknown="$((nuclei_unknown + count))" ;;
    esac
  done < <(
    jq -r '.info.severity // "unknown"' "$NUCLEI_JSONL" 2>/dev/null \
      | awk '{counts[$1]++} END {for (k in counts) print k "=" counts[k]}'
  )
fi

nikto_total="0"
if [[ -f "$NIKTO_TXT" ]]; then
  nikto_total="$(awk '/^\+ / {c++} END {print c+0}' "$NIKTO_TXT")"
fi

sqlmap_total="0"
sqlmap_file="not-found"
sqlmap_dump_tables="0"
sqlmap_users_rows="0"
shopt -s nullglob
sqlmap_candidates=(labs/lab5/sqlmap/*/results-*.csv)
shopt -u nullglob
if (( ${#sqlmap_candidates[@]} > 0 )); then
  sqlmap_file="${sqlmap_candidates[0]}"
  sqlmap_total="$(awk 'NR>1 && $0 !~ /^[[:space:]]*$/ {c++} END {print c+0}' "$sqlmap_file")"
elif [[ -f "labs/lab5/sqlmap/localhost/target.txt" ]]; then
  # Older sqlmap versions store confirmation in target/log and dump separate table CSV files.
  sqlmap_file="labs/lab5/sqlmap/localhost/target.txt"
  sqlmap_total="1"
  shopt -s nullglob
  dump_tables=(labs/lab5/sqlmap/localhost/dump/SQLite_masterdb/*.csv)
  shopt -u nullglob
  sqlmap_dump_tables="${#dump_tables[@]}"
  if [[ -f "labs/lab5/sqlmap/localhost/dump/SQLite_masterdb/Users.csv" ]]; then
    sqlmap_users_rows="$(awk 'NR>1 && $0 !~ /^[[:space:]]*$/ {c++} END {print c+0}' labs/lab5/sqlmap/localhost/dump/SQLite_masterdb/Users.csv)"
  fi
fi

{
  echo "=== DAST Multi-Tool Summary ==="
  echo
  echo "Tool comparison matrix:"
  echo "| Tool | Findings | Severity Breakdown | Best Use Case |"
  echo "|---|---:|---|---|"
  echo "| ZAP (unauth) | $zap_noauth_total | See report-noauth (mostly Medium/Low) | Public attack-surface baseline |"
  echo "| ZAP (auth) | $zap_auth_total | High=$zap_auth_high, Medium=$zap_auth_medium, Low=$zap_auth_low, Info=$zap_auth_info | Full app scan with authenticated workflows |"
  echo "| Nuclei | $nuclei_total | Critical=$nuclei_critical, High=$nuclei_high, Medium=$nuclei_medium, Low=$nuclei_low, Info=$nuclei_info, Unknown=$nuclei_unknown | Fast template-based CVE/config checks |"
  echo "| Nikto | $nikto_total | Text-based checks (server-side issues) | Web server misconfiguration discovery |"
  echo "| SQLmap | $sqlmap_total | SQLi endpoints=$sqlmap_total, dumped tables=$sqlmap_dump_tables, Users rows=$sqlmap_users_rows | Deep SQL injection validation and extraction |"
  echo
  echo "SQLmap evidence file: $sqlmap_file"
} > "$OUT_FILE"

cat "$OUT_FILE"
