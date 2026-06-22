#!/usr/bin/env bash
# Compare baseline and authenticated ZAP reports.

set -euo pipefail

BASELINE="${1:-labs/lab5/results/baseline-report.json}"
AUTH="${2:-labs/lab5/results/auth-report.json}"

parse_report() {
  local file="$1"
  local label="$2"

  if [[ ! -f "$file" ]]; then
    echo "$label: report not found: $file"
    return 1
  fi

  echo "$label:"
  jq -r '
    [ .site[].alerts[] ] as $alerts |
    "  Total alerts: \($alerts | length)",
    "  High: \($alerts | map(select(.riskcode == "3")) | length)",
    "  Medium: \($alerts | map(select(.riskcode == "2")) | length)",
    "  Low: \($alerts | map(select(.riskcode == "1")) | length)",
    "  Informational: \($alerts | map(select(.riskcode == "0")) | length)",
    "  Unique URLs with findings: \(
      [ $alerts[].instances[].uri ] | unique | length
    )"
  ' "$file"
}

baseline_total=$(jq '[.site[].alerts[]] | length' "$BASELINE")
auth_total=$(jq '[.site[].alerts[]] | length' "$AUTH")

echo "ZAP scan comparison"
echo
parse_report "$BASELINE" "Baseline (unauthenticated)"
echo
parse_report "$AUTH" "Authenticated full scan"
echo

if [[ "$baseline_total" -gt 0 ]]; then
  ratio=$(awk "BEGIN { printf \"%.2f\", $auth_total / $baseline_total }")
  echo "Auth/baseline ratio: ${ratio}x"
else
  echo "Auth/baseline ratio: undefined (baseline has zero alerts)"
fi
