#!/usr/bin/env bash
set -euo pipefail

# Batch import helper for Lab 10
# - Auto-detects scan_type names from your Dojo instance
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

here_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out_dir="$here_dir"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: env var $name is required" >&2
    exit 1
  fi
}

require_env DD_API
require_env DD_TOKEN

DD_PRODUCT_TYPE="${DD_PRODUCT_TYPE:-Engineering}"
DD_PRODUCT="${DD_PRODUCT:-Juice Shop}"
DD_ENGAGEMENT="${DD_ENGAGEMENT:-Labs Security Testing}"

echo "Using context:"
echo "  DD_API=$DD_API"
echo "  DD_PRODUCT_TYPE=$DD_PRODUCT_TYPE"
echo "  DD_PRODUCT=$DD_PRODUCT"
echo "  DD_ENGAGEMENT=$DD_ENGAGEMENT"

have_jq=true
command -v jq >/dev/null 2>&1 || have_jq=false
if ! $have_jq; then
  echo "WARN: jq not found; falling back to defaults for scan_type names." >&2
fi

# Discover scan type names from your instance if jq is available
SCAN_ZAP="${SCAN_ZAP:-}"
SCAN_SEMGREP="${SCAN_SEMGREP:-}"
SCAN_TRIVY="${SCAN_TRIVY:-}"
SCAN_NUCLEI="${SCAN_NUCLEI:-}"

if $have_jq; then
  echo "Discovering importer names from /test_types/ ..."
  mapfile -t types < <(curl -sS -H "Authorization: Token $DD_TOKEN" "$DD_API/test_types/?limit=2000" | jq -r '.results[].name')
  choose_type() {
    local pat="$1"
    local fallback="$2"
    local val=""
    for t in "${types[@]}"; do
      if [[ "$t" =~ $pat ]]; then val="$t"; break; fi
    done
    if [[ -z "$val" ]]; then val="$fallback"; fi
    echo "$val"
  }
  SCAN_ZAP="${SCAN_ZAP:-$(choose_type '^ZAP' 'ZAP Scan')}"
  SCAN_SEMGREP="${SCAN_SEMGREP:-$(choose_type '^Semgrep' 'Semgrep JSON Report')}"
  SCAN_TRIVY="${SCAN_TRIVY:-$(choose_type '^Trivy' 'Trivy Scan')}"
  SCAN_NUCLEI="${SCAN_NUCLEI:-$(choose_type '^Nuclei' 'Nuclei Scan')}"
  # Grype importer (commonly named "Anchore Grype")
  if [[ -z "${SCAN_GRYPE:-}" ]]; then
    SCAN_GRYPE=$(printf '%s\n' "${types[@]}" | grep -i '^Anchore Grype' | head -n1)
    if [[ -z "$SCAN_GRYPE" ]]; then
      SCAN_GRYPE=$(printf '%s\n' "${types[@]}" | grep -i 'Grype' | head -n1)
    fi
  fi
else
  SCAN_ZAP="${SCAN_ZAP:-ZAP Scan}"
  SCAN_SEMGREP="${SCAN_SEMGREP:-Semgrep JSON Report}"
  SCAN_TRIVY="${SCAN_TRIVY:-Trivy Scan}"
  SCAN_NUCLEI="${SCAN_NUCLEI:-Nuclei Scan}"
fi
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
  if [[ ! -f "$file" ]]; then
    echo "SKIP: $scan_type file not found: $file"
    return 0
  fi
  local base out
  base="$(basename "$file")"
  out="$out_dir/import-${base//[^A-Za-z0-9_.-]/_}.json"
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
