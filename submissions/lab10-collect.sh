#!/bin/bash
# Collect DefectDojo metrics for submissions/lab10.md — run AFTER imports
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

: "${DD_URL:?source labs/lab10/imports/env.sh first}"
: "${DD_TOKEN:?source labs/lab10/imports/env.sh first}"
: "${DD_ENGAGEMENT_ID:?run run-imports.sh first or set DD_ENGAGEMENT_ID}"

auth=(-H "Authorization: Token ${DD_TOKEN}")
mkdir -p labs/lab10/work

echo "========== LAB10 COLLECT =========="
echo "--- DefectDojo version ---"
docker compose -f labs/lab10/work/dd/docker-compose.yml images 2>/dev/null | head -5 || echo "(run from labs/lab10/work/dd if needed)"

echo "--- Product / Engagement ---"
echo "DD_PRODUCT_ID=$DD_PRODUCT_ID"
echo "DD_ENGAGEMENT_ID=$DD_ENGAGEMENT_ID"

echo "--- Import summary ---"
cat labs/lab10/work/import-summary.tsv 2>/dev/null || echo "MISSING — run bash labs/lab10/imports/run-imports.sh"

echo "--- Total findings (deduped) ---"
curl -sS "${auth[@]}" "${DD_URL}/api/v2/findings/?engagement=${DD_ENGAGEMENT_ID}&limit=1" | jq '{count: .count}'

echo "--- Active by severity ---"
curl -sS "${auth[@]}" "${DD_URL}/api/v2/findings/?engagement=${DD_ENGAGEMENT_ID}&active=true&limit=200" | \
  jq '[.results[] | .severity] | group_by(.) | map({severity: .[0], count: length})'

echo "--- Dedup check CVE-2024-21626 (if present) ---"
curl -sS "${auth[@]}" "${DD_URL}/api/v2/findings/?engagement=${DD_ENGAGEMENT_ID}&cve=CVE-2024-21626" | \
  jq '{count: .count, ids: [.results[].id]}'

echo "--- Mitigated count ---"
curl -sS "${auth[@]}" "${DD_URL}/api/v2/findings/?engagement=${DD_ENGAGEMENT_ID}&is_mitigated=true&limit=1" | jq '{count: .count}'

echo "--- Risk accepted ---"
curl -sS "${auth[@]}" "${DD_URL}/api/v2/findings/?engagement=${DD_ENGAGEMENT_ID}&risk_accepted=true&limit=50" | \
  jq '[.results[] | {id, title, severity, risk_accepted_expiration: .risk_accepted_expiration}]'

echo "========== DONE — paste into submissions/lab10.md =========="
