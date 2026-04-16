#!/usr/bin/env bash
set -euo pipefail

DD_API="${DD_API:-http://localhost:8080/api/v2}"
DD_TOKEN="${DD_TOKEN:?DD_TOKEN is not set}"
DD_PRODUCT_TYPE="${DD_PRODUCT_TYPE:-Engineering}"
DD_PRODUCT="${DD_PRODUCT:-Juice Shop}"
DD_ENGAGEMENT="${DD_ENGAGEMENT:-Labs Security Testing}"

OUT_DIR="labs/lab10/imports"
SRC_DIR="labs/lab10/imports/source-reports"
mkdir -p "$OUT_DIR"

auth_header="Authorization: Token $DD_TOKEN"

urlencode() {
  python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"
}

get_first_id() {
  local endpoint="$1"
  local query_name="$2"
  curl -s -H "$auth_header" "$DD_API/$endpoint/?name=$(urlencode "$query_name")" | jq -r '.results[0].id // empty'
}

create_product_type() {
  curl -s -X POST "$DD_API/product_types/" \
    -H "$auth_header" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$DD_PRODUCT_TYPE\",\"description\":\"Created by lab10 importer\"}" \
    | tee "$OUT_DIR/product-type.json" | jq -r '.id'
}

create_product() {
  local pt_id="$1"
  curl -s -X POST "$DD_API/products/" \
    -H "$auth_header" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$DD_PRODUCT\",\"description\":\"Created by lab10 importer\",\"prod_type\":$pt_id}" \
    | tee "$OUT_DIR/product.json" | jq -r '.id'
}

create_engagement() {
  local product_id="$1"
  local today enddate
  today=$(date +%F)
  enddate=$(python3 - <<'PY'
from datetime import date, timedelta
print((date.today()+timedelta(days=30)).isoformat())
PY
)
  curl -s -X POST "$DD_API/engagements/" \
    -H "$auth_header" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\":\"$DD_ENGAGEMENT\",
      \"description\":\"Created by lab10 importer\",
      \"product\":$product_id,
      \"target_start\":\"$today\",
      \"target_end\":\"$enddate\",
      \"status\":\"In Progress\",
      \"engagement_type\":\"CI/CD\"
    }" | tee "$OUT_DIR/engagement.json" | jq -r '.id'
}

import_scan() {
  local scan_type="$1"
  local file_path="$2"
  local label="$3"

  if [[ ! -f "$file_path" ]]; then
    echo "[!] Skipping $label: missing $file_path"
    return 0
  fi

  echo "[*] Importing $label with scan_type='$scan_type' from $file_path"
  curl -s -X POST "$DD_API/import-scan/" \
    -H "$auth_header" \
    -F "engagement=$ENGAGEMENT_ID" \
    -F "scan_type=$scan_type" \
    -F "active=true" \
    -F "verified=true" \
    -F "close_old_findings=false" \
    -F "file=@$file_path" \
    | tee "$OUT_DIR/$label.json"
  echo
}

echo "[*] Ensuring Product Type exists..."
PT_ID="$(get_first_id product_types "$DD_PRODUCT_TYPE")"
if [[ -z "$PT_ID" ]]; then
  PT_ID="$(create_product_type)"
fi
echo "[+] Product Type ID: $PT_ID"

echo "[*] Ensuring Product exists..."
PRODUCT_ID="$(get_first_id products "$DD_PRODUCT")"
if [[ -z "$PRODUCT_ID" ]]; then
  PRODUCT_ID="$(create_product "$PT_ID")"
fi
echo "[+] Product ID: $PRODUCT_ID"

echo "[*] Ensuring Engagement exists..."
ENGAGEMENT_ID="$(get_first_id engagements "$DD_ENGAGEMENT")"
if [[ -z "$ENGAGEMENT_ID" ]]; then
  ENGAGEMENT_ID="$(create_engagement "$PRODUCT_ID")"
fi
echo "[+] Engagement ID: $ENGAGEMENT_ID"

import_scan "Semgrep JSON Report" "$SRC_DIR/semgrep-results.json" "semgrep"
import_scan "Trivy Scan" "$SRC_DIR/trivy-results.json" "trivy"
import_scan "Anchore Grype" "$SRC_DIR/grype-results.json" "grype"

echo "[+] Imports completed."
