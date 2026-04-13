#!/bin/bash
set -e

DD_API="http://localhost:8080/api/v2"
export DD_TOKEN="<your-api-token-from-profile>"
ENG_ID=1

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

import_scan() {
  local scan_type="$1"
  local file="$2"
  local label="$3"

  if [ ! -f "$file" ]; then
    echo "SKIP $label — file not found: $file"
    return
  fi

  echo "Importing $label ($scan_type)..."
  RESPONSE=$(curl -s -X POST "$DD_API/import-scan/" \
    -H "Authorization: Token $DD_TOKEN" \
    -F "scan_type=$scan_type" \
    -F "file=@$file" \
    -F "engagement=$ENG_ID" \
    -F "active=true" \
    -F "verified=false" \
    -F "close_old_findings=false")

  echo "$RESPONSE" | jq '{test: .test, findings_count: .findings_count}' 2>/dev/null || echo "$RESPONSE"
  echo "$RESPONSE" > "$REPO_ROOT/labs/lab10/imports/${label}-response.json"
  echo "Done: $label"
  echo ""
}

echo "=== DefectDojo Import Script ==="
echo "Engagement ID: $ENG_ID"
echo ""

import_scan "ZAP Scan"     "$REPO_ROOT/labs/lab5/zap/zap-report-noauth.json"      "zap-noauth"
import_scan "ZAP Scan"     "$REPO_ROOT/labs/lab5/zap/zap-report-auth.json"        "zap-auth"
import_scan "Semgrep JSON" "$REPO_ROOT/labs/lab5/semgrep/semgrep-results.json"    "semgrep"
import_scan "Nuclei Scan"  "$REPO_ROOT/labs/lab5/nuclei/nuclei-results.json"      "nuclei"
import_scan "Trivy Scan"   "$REPO_ROOT/labs/lab4/trivy/trivy-vuln-detailed.json"  "trivy"
import_scan "Grype"        "$REPO_ROOT/labs/lab4/syft/grype-vuln-results.json"    "grype"

echo "=== Import complete ==="
