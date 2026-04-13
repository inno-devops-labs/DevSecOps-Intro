#!/usr/bin/env bash
set -euo pipefail

# Batch import helper for Lab 10 (macOS-compatible)
# - Uses hardcoded scan_type names (known-good defaults for DefectDojo)
# - Imports whichever files exist among ZAP, Semgrep, Trivy, Nuclei (and optional Grype)
#
# Usage:
#   export DD_API="http://localhost:8080/api/v2"
#   export DD_TOKEN="<your_api_token>"
#   # Optional overrides (defaults shown)
#   export DD_PRODUCT_TYPE="${DD_PRODUCT_TYPE:-Engineering}"
#   export DD_PRODUCT="${DD_PRODUCT:-Juice Shop}"
#   export DD_ENGAGEMENT="${DD_ENGAGEMENT:-Labs Security Testing}"
#   bash labs/lab10/imports/run-imports.sh

here_dir="$(cd "$(dirname "$0")" && pwd)"
out_dir="$here_dir"

if [ -z "${DD_API:-}" ]; then
  echo "ERROR: env var DD_API is required" >&2
  exit 1
fi
if [ -z "${DD_TOKEN:-}" ]; then
  echo "ERROR: env var DD_TOKEN is required" >&2
  exit 1
fi

DD_PRODUCT_TYPE="${DD_PRODUCT_TYPE:-Engineering}"
DD_PRODUCT="${DD_PRODUCT:-Juice Shop}"
DD_ENGAGEMENT="${DD_ENGAGEMENT:-Labs Security Testing}"

echo "Using context:"
echo "  DD_API=$DD_API"
echo "  DD_PRODUCT_TYPE=$DD_PRODUCT_TYPE"
echo "  DD_PRODUCT=$DD_PRODUCT"
echo "  DD_ENGAGEMENT=$DD_ENGAGEMENT"

# Use known scan_type names for DefectDojo
SCAN_ZAP="${SCAN_ZAP:-ZAP Scan}"
SCAN_SEMGREP="${SCAN_SEMGREP:-Semgrep JSON Report}"
SCAN_TRIVY="${SCAN_TRIVY:-Trivy Scan}"
SCAN_NUCLEI="${SCAN_NUCLEI:-Nuclei Scan}"
SCAN_GRYPE="${SCAN_GRYPE:-Anchore Grype}"

echo "Importer names:"
echo "  ZAP      = $SCAN_ZAP"
echo "  Semgrep  = $SCAN_SEMGREP"
echo "  Trivy    = $SCAN_TRIVY"
echo "  Nuclei   = $SCAN_NUCLEI"
echo "  Grype    = $SCAN_GRYPE"

import_scan() {
  local scan_type="$1"; shift
  local file="$1"; shift
  if [ ! -f "$file" ]; then
    echo "SKIP: $scan_type file not found: $file"
    return 0
  fi
  local base out
  base="$(basename "$file")"
  out="$out_dir/import-$(echo "$base" | sed 's/[^A-Za-z0-9_.-]/_/g').json"
  echo "Importing $scan_type from $file"
  curl -sS -X POST "$DD_API/import-scan/" \
    -H "Authorization: Token $DD_TOKEN" \
    -F "scan_type=$scan_type" \
    -F "file=@$file" \
    -F "product_type_name=$DD_PRODUCT_TYPE" \
    -F "product_name=$DD_PRODUCT" \
    -F "engagement_name=$DD_ENGAGEMENT" \
    -F "auto_create_context=true" \
    -F "minimum_severity=Info" \
    -F "close_old_findings=false" \
    -F "push_to_jira=false" \
    | tee "$out"
  echo ""
}

# Candidate paths per tool
zap_file="labs/lab5/zap/zap-report-noauth.json"
semgrep_file="labs/lab5/semgrep/semgrep-results.json"
trivy_file="labs/lab4/trivy/trivy-vuln-detailed.json"
nuclei_file="labs/lab5/nuclei/nuclei-results.json"

# Grype
grype_file="labs/lab4/syft/grype-vuln-results.json"

import_scan "$SCAN_ZAP"     "$zap_file"
import_scan "$SCAN_SEMGREP" "$semgrep_file"
import_scan "$SCAN_TRIVY"   "$trivy_file"
import_scan "$SCAN_NUCLEI"  "$nuclei_file"

# Grype
import_scan "$SCAN_GRYPE" "$grype_file"

echo "Done. Import responses saved under $out_dir"
