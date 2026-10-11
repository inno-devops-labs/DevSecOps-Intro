#!/usr/bin/env bash
set -euo pipefail

# Batch import helper for Lab 10.
# Imports every Lab 4-7 scan report that exists into DefectDojo, auto-detecting
# the scan_type names from your instance (with sane fallbacks if discovery fails).
#
# Usage:
#   export DD_URL="http://localhost:8080"     # base URL (same as lab10.md step 10.2)
#   export DD_TOKEN="<your_api_token>"         # Profile -> API v2 Key in the UI
#   bash labs/lab10/imports/run-imports.sh
#
# Optional overrides (defaults shown):
#   DD_API="$DD_URL/api/v2"
#   DD_PRODUCT_TYPE="Engineering"
#   DD_PRODUCT="OWASP Juice Shop"
#   DD_ENGAGEMENT="Course Semester Run"
#
# File paths are resolved relative to the repo root, so the script runs from any
# directory. Portable to bash 3.2 (stock macOS) — no mapfile/readarray.

here_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out_dir="$here_dir"
repo_root="$(cd "$here_dir/../../.." && pwd)"   # labs/lab10/imports -> repo root

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: env var $name is required" >&2
    exit 1
  fi
}

require_env DD_TOKEN

failures=0

DD_URL="${DD_URL:-http://localhost:8080}"
DD_API="${DD_API:-$DD_URL/api/v2}"
# Must match the product type of an existing product with this name, or the API
# rejects every import with a product-type conflict. "Research and Development"
# is what a stock DefectDojo has as product type id 1, which is what lab10.md
# creates the product with.
DD_PRODUCT_TYPE="${DD_PRODUCT_TYPE:-Research and Development}"
DD_PRODUCT="${DD_PRODUCT:-OWASP Juice Shop}"
DD_ENGAGEMENT="${DD_ENGAGEMENT:-Course Semester Run}"

echo "Using context:"
echo "  DD_API=$DD_API"
echo "  DD_PRODUCT_TYPE=$DD_PRODUCT_TYPE"
echo "  DD_PRODUCT=$DD_PRODUCT"
echo "  DD_ENGAGEMENT=$DD_ENGAGEMENT"

have_jq=true
command -v jq >/dev/null 2>&1 || have_jq=false
$have_jq || echo "WARN: jq not found; using default scan_type names." >&2

# Discover scan_type names from the instance. Fallbacks keep the script working
# even if discovery fails (no jq, instance not up, auth error).
types=()
if $have_jq; then
  echo "Discovering importer names from /test_types/ ..."
  while IFS= read -r name; do
    [[ -n "$name" ]] && types+=("$name")
  done < <(curl -sS -H "Authorization: Token $DD_TOKEN" \
             "$DD_API/test_types/?limit=2000" 2>/dev/null | jq -r '.results[].name' 2>/dev/null)
fi

choose_type() {
  local pat="$1" fallback="$2" t
  if [[ ${#types[@]} -gt 0 ]]; then
    for t in "${types[@]}"; do
      if [[ "$t" =~ $pat ]]; then echo "$t"; return; fi
    done
  fi
  echo "$fallback"
}

SCAN_GRYPE="$(choose_type '^Anchore Grype' 'Anchore Grype')"
SCAN_TRIVY="$(choose_type '^Trivy Scan$' 'Trivy Scan')"
SCAN_TRIVY_OP="$(choose_type '^Trivy Operator' 'Trivy Operator Scan')"
# Anchored: DefectDojo also ships "Semgrep Pro JSON Report", which does not
# parse community `semgrep --json` output.
SCAN_SEMGREP="$(choose_type '^Semgrep JSON Report$' 'Semgrep JSON Report')"
SCAN_ZAP="$(choose_type '^ZAP' 'ZAP Scan')"
SCAN_CHECKOV="$(choose_type '^Checkov' 'Checkov Scan')"
SCAN_KICS="$(choose_type '^KICS' 'KICS Scan')"

echo "Importer names:"
echo "  Grype          = $SCAN_GRYPE"
echo "  Trivy          = $SCAN_TRIVY"
echo "  Trivy Operator = $SCAN_TRIVY_OP"
echo "  Semgrep        = $SCAN_SEMGREP"
echo "  ZAP            = $SCAN_ZAP"
echo "  Checkov        = $SCAN_CHECKOV"
echo "  KICS           = $SCAN_KICS"

import_scan() {
  local scan_type="$1" file="$2"
  local rel="${file#"$repo_root"/}"
  # Resume a failed import without creating new tests for successful reports.
  if [[ -n "${DD_IMPORT_ONLY:-}" && "$(basename "$file")" != "$DD_IMPORT_ONLY" ]]; then
    return 0
  fi
  if [[ ! -f "$file" ]]; then
    echo "SKIP: $scan_type — file not found: $rel"
    return 0
  fi
  # The pinned ZAP parser accepts XML only. Trivy CLI k8s output is not an
  # Operator CRD; adapt its newer Findings key for the regular Trivy parser.
  local source_file="$file"
  case "$(basename "$file")" in
    auth-report.json)
      file="$repo_root/labs/lab10/work/converted/auth-report.xml"
      python3 "$here_dir/prepare-report.py" zap "$source_file" "$file"
      echo "Adapted $rel to ZAP XML (same alert evidence)"
      ;;
    trivy-k8s.json)
      file="$repo_root/labs/lab10/work/converted/trivy-k8s.json"
      python3 "$here_dir/prepare-report.py" trivy-k8s "$source_file" "$file"
      echo "Adapted $rel: Findings -> Resources (same resource evidence)"
      ;;
  esac
  local tag base out
  tag="$(basename "$(dirname "$file")")"; tag="${tag//[^A-Za-z0-9_.-]/_}"
  base="$(basename "$file")";             base="${base//[^A-Za-z0-9_.-]/_}"
  out="$out_dir/import-${tag}-${base}"
  echo "Importing $scan_type from $rel"
  local code
  code="$(curl -sS -o "$out" -w '%{http_code}' -X POST "$DD_API/import-scan/" \
      -H "Authorization: Token $DD_TOKEN" \
      -F "scan_type=$scan_type" \
      -F "file=@$file" \
      -F "product_type_name=$DD_PRODUCT_TYPE" \
      -F "product_name=$DD_PRODUCT" \
      -F "engagement_name=$DD_ENGAGEMENT" \
      -F "auto_create_context=true" \
      -F "minimum_severity=Info" \
      -F "close_old_findings=false" \
      -F "push_to_jira=false")" || code="000"
  # A 400 from DefectDojo still exits curl 0, so check the status. Silent
  # failures here are how a student ends up with an empty dashboard and no idea why.
  case "$code" in
    2*)
      if $have_jq; then
        echo "  ok: test $(jq -r '.test // "?"' "$out"), $(jq -r '.statistics.after.total.active // "?"' "$out") active findings"
      else
        echo "  ok (HTTP $code)"
      fi
      ;;
    *)
      echo "  FAILED: HTTP $code for $scan_type ($base)" >&2
      if $have_jq; then jq -r '.[]? // .detail? // .' "$out" 2>/dev/null | head -3 | sed 's/^/    /' >&2; fi
      failures=$((failures + 1))
      ;;
  esac
}

# Lab 4 — SCA (SBOM-derived)
import_scan "$SCAN_GRYPE"    "$repo_root/labs/lab4/grype-from-sbom.json"
import_scan "$SCAN_TRIVY"    "$repo_root/labs/lab4/trivy.json"
# Lab 5 — DAST + SAST
import_scan "$SCAN_SEMGREP"  "$repo_root/labs/lab5/results/semgrep.json"
import_scan "$SCAN_ZAP"      "$repo_root/labs/lab5/results/auth-report.json"
# Lab 6 — IaC
import_scan "$SCAN_CHECKOV"  "$repo_root/labs/lab6/results/checkov-terraform/results_json.json"
import_scan "$SCAN_KICS"     "$repo_root/labs/lab6/results/kics-ansible/results.json"
import_scan "$SCAN_KICS"     "$repo_root/labs/lab6/results/kics-pulumi/results.json"
# Lab 7 — Container image + K8s
import_scan "$SCAN_TRIVY"    "$repo_root/labs/lab7/results/trivy-image.json"
import_scan "$SCAN_TRIVY"    "$repo_root/labs/lab7/results/trivy-k8s.json"

if [[ $failures -gt 0 ]]; then
  echo "Done with $failures failed import(s). Responses are under $out_dir" >&2
  exit 1
fi
echo "Done. Import responses saved under $out_dir"
