#!/usr/bin/env bash
set -euo pipefail

# Batch import helper for Lab 10
# - Auto-detects scan_type names from your Dojo instance
# - Imports whichever files exist among ZAP, Semgrep, Trivy, Nuclei (and optional Grype)
# - Uses /reimport-scan so repeated runs update the latest matching test instead of
#   creating a fresh duplicate test on every execution
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
repo_root="$(cd "$here_dir/../../.." && pwd)"
out_dir="$here_dir"
failures=0

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

# Default scan type names. These are also used as a fallback when importer
# discovery is unavailable.
SCAN_ZAP="${SCAN_ZAP:-ZAP Scan}"
SCAN_SEMGREP="${SCAN_SEMGREP:-Semgrep JSON Report}"
SCAN_TRIVY="${SCAN_TRIVY:-Trivy Scan}"
SCAN_NUCLEI="${SCAN_NUCLEI:-Nuclei Scan}"
SCAN_GRYPE="${SCAN_GRYPE:-Anchore Grype}"

if $have_jq; then
  echo "Discovering importer names from /test_types/ ..."
  if types_json="$(curl -fsS -H "Authorization: Token $DD_TOKEN" "$DD_API/test_types/?limit=2000")"; then
    if type_names="$(printf '%s' "$types_json" | jq -er '.results[].name' 2>/dev/null)"; then
      mapfile -t types <<<"$type_names"
      choose_type() {
        local exact="$1"
        local pat="$2"
        local fallback="$3"
        local val=""
        for t in "${types[@]}"; do
          if [[ "$t" == "$exact" ]]; then
            val="$t"
            break
          fi
        done
        if [[ -z "$val" ]]; then
          for t in "${types[@]}"; do
            if [[ "$t" =~ $pat ]]; then
              val="$t"
              break
            fi
          done
        fi
        if [[ -z "$val" ]]; then val="$fallback"; fi
        echo "$val"
      }
      SCAN_ZAP="$(choose_type 'ZAP Scan' '^ZAP' "$SCAN_ZAP")"
      SCAN_SEMGREP="$(choose_type 'Semgrep JSON Report' '^Semgrep' "$SCAN_SEMGREP")"
      SCAN_TRIVY="$(choose_type 'Trivy Scan' '^Trivy' "$SCAN_TRIVY")"
      SCAN_NUCLEI="$(choose_type 'Nuclei Scan' '^Nuclei' "$SCAN_NUCLEI")"
      grype_name="$(printf '%s\n' "${types[@]}" | grep -i '^Anchore Grype' | head -n1 || true)"
      if [[ -z "$grype_name" ]]; then
        grype_name="$(printf '%s\n' "${types[@]}" | grep -i 'Grype' | head -n1 || true)"
      fi
      if [[ -n "$grype_name" ]]; then
        SCAN_GRYPE="$grype_name"
      fi
    else
      echo "WARN: received an unexpected /test_types/ response; using default scan_type names." >&2
    fi
  else
    echo "WARN: failed to query /test_types/; using default scan_type names." >&2
  fi
fi

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
  local base out http_code test_id total
  base="$(basename "$file")"
  out="$out_dir/import-${base//[^A-Za-z0-9_.-]/_}.json"
  echo "Uploading $scan_type from $file via reimport-scan"
  if ! http_code="$(
    curl -sS -o "$out" -w "%{http_code}" -X POST "$DD_API/reimport-scan/" \
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
  )"; then
    echo "ERROR: $scan_type import request failed"
    if [[ -s "$out" ]]; then
      cat "$out"
    fi
    failures=$((failures + 1))
    return 0
  fi

  if [[ ! "$http_code" =~ ^2 ]]; then
    echo "ERROR: $scan_type import returned HTTP $http_code"
    cat "$out"
    failures=$((failures + 1))
    return 0
  fi

  if $have_jq && jq -e '.test // .test_id' "$out" >/dev/null 2>&1; then
    test_id="$(jq -r '.test // .test_id' "$out")"
    total="$(jq -r '.statistics.after.total.total // .statistics.after.total.active // "unknown"' "$out")"
    echo "OK: $scan_type imported successfully (test_id=$test_id, total_findings=$total)"
    return 0
  fi

  if ! $have_jq; then
    echo "OK: $scan_type imported successfully (jq unavailable; response saved to $out)"
    return 0
  fi

  echo "ERROR: $scan_type import response did not include a test identifier"
  cat "$out"
  failures=$((failures + 1))
}

# Candidate paths per tool
zap_json_file="$repo_root/labs/lab5/zap/zap-report-noauth.json"
zap_xml_file="$repo_root/labs/lab5/zap/zap-report-noauth.xml"
semgrep_file="$repo_root/labs/lab5/semgrep/semgrep-results.json"
trivy_file="$repo_root/labs/lab4/trivy/trivy-vuln-detailed.json"
nuclei_file="$repo_root/labs/lab5/nuclei/nuclei-results.json"

# Grype
grype_file="$repo_root/labs/lab4/syft/grype-vuln-results.json"

zap_file="$zap_json_file"
if [[ "$SCAN_ZAP" == "ZAP Scan" && -f "$zap_xml_file" ]]; then
  # Current DefectDojo ZAP parser expects XML, even if the lab also keeps JSON output.
  zap_file="$zap_xml_file"
fi

import_scan "$SCAN_ZAP"     "$zap_file"
import_scan "$SCAN_SEMGREP" "$semgrep_file"
import_scan "$SCAN_TRIVY"   "$trivy_file"
import_scan "$SCAN_NUCLEI"  "$nuclei_file"

# Grype
import_scan "$SCAN_GRYPE" "$grype_file"

if (( failures > 0 )); then
  echo "Done with $failures failed import(s). Responses saved under $out_dir" >&2
  exit 1
fi

echo "Done. Import responses saved under $out_dir"
