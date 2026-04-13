#!/usr/bin/env bash
set -euo pipefail

: "${DD_API:?DD_API is required}"
: "${DD_TOKEN:?DD_TOKEN is required}"

DD_PRODUCT_TYPE="${DD_PRODUCT_TYPE:-Engineering}"
DD_PRODUCT="${DD_PRODUCT:-Juice Shop}"
DD_ENGAGEMENT="${DD_ENGAGEMENT:-Labs Security Testing Final}"
SCAN_ZAP="${SCAN_ZAP:-ZAP Scan}"

zap_file="labs/lab5/zap/zap-report-noauth.xml"
out_dir="labs/lab10/imports"
mkdir -p "$out_dir"

curl -sS -X POST "$DD_API/import-scan/" \
  -H "Authorization: Token $DD_TOKEN" \
  -F "scan_type=$SCAN_ZAP" \
  -F "file=@$zap_file" \
  -F "product_type_name=$DD_PRODUCT_TYPE" \
  -F "product_name=$DD_PRODUCT" \
  -F "engagement_name=$DD_ENGAGEMENT" \
  -F "auto_create_context=true" \
  -F "minimum_severity=Info" \
  -F "close_old_findings=false" \
  -F "push_to_jira=false" \
  | tee "$out_dir/import-zap-report-noauth.xml.json"
