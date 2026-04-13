#!/usr/bin/env bash
set -euo pipefail

DD_API="${DD_API:-http://localhost:8080/api/v2}"
DD_TOKEN="${DD_TOKEN:?Set DD_TOKEN env var first}"
PRODUCT_TYPE="${DD_PRODUCT_TYPE:-Engineering}"
PRODUCT="${DD_PRODUCT:-Juice Shop}"
ENGAGEMENT="${DD_ENGAGEMENT:-Labs Security Testing}"

AUTH_H="Authorization: Token $DD_TOKEN"
CT_H="Content-Type: application/json"

# Simple JSON field extractor — no python3/jq dependency
json_field() {
  local field="$1" json="$2"
  echo "$json" | grep -o "\"${field}\":[^,}]*" | head -1 | sed 's/.*: *//' | tr -d '"'
}

# URL-encode: replace spaces with %20
urlencode() { echo "${1// /%20}"; }

# Convert ZAP JSON report to ZAP XML (which DefectDojo expects for "ZAP Scan")
convert_zap_json_to_xml() {
  local json_file="$1" xml_file="$2"
  python -c "
import json, sys

def esc(s):
    if s is None: return ''
    return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('\"','&quot;')

with open('$json_file', encoding='utf-8') as f:
    d = json.load(f)

lines = ['<?xml version=\"1.0\" encoding=\"UTF-8\"?>']
lines.append('<OWASPZAPReport version=\"{}\" generated=\"{}\">'.format(
    esc(d.get('@version','')), esc(d.get('@generated',''))))

for site in d.get('site', []):
    lines.append('  <site name=\"{}\" host=\"{}\" port=\"{}\" ssl=\"{}\">'.format(
        esc(site.get('@name','')), esc(site.get('@host','')),
        esc(site.get('@port','')), esc(site.get('@ssl','false'))))
    lines.append('    <alerts>')
    for a in site.get('alerts', []):
        lines.append('      <alertitem>')
        lines.append('        <pluginid>{}</pluginid>'.format(esc(a.get('pluginid',''))))
        lines.append('        <alert>{}</alert>'.format(esc(a.get('alert',''))))
        lines.append('        <name>{}</name>'.format(esc(a.get('name',a.get('alert','')))))
        lines.append('        <riskcode>{}</riskcode>'.format(esc(a.get('riskcode',''))))
        lines.append('        <confidence>{}</confidence>'.format(esc(a.get('confidence',''))))
        lines.append('        <riskdesc>{}</riskdesc>'.format(esc(a.get('riskdesc',''))))
        lines.append('        <desc>{}</desc>'.format(esc(a.get('desc',''))))
        lines.append('        <solution>{}</solution>'.format(esc(a.get('solution',''))))
        lines.append('        <reference>{}</reference>'.format(esc(a.get('reference',''))))
        lines.append('        <cweid>{}</cweid>'.format(esc(a.get('cweid',''))))
        lines.append('        <wascid>{}</wascid>'.format(esc(a.get('wascid',''))))
        lines.append('        <instances>')
        for inst in a.get('instances', []):
            lines.append('          <instance>')
            lines.append('            <uri>{}</uri>'.format(esc(inst.get('uri',''))))
            lines.append('            <method>{}</method>'.format(esc(inst.get('method',''))))
            lines.append('            <param>{}</param>'.format(esc(inst.get('param',''))))
            lines.append('            <evidence>{}</evidence>'.format(esc(inst.get('evidence',''))))
            lines.append('          </instance>')
        lines.append('        </instances>')
        lines.append('      </alertitem>')
    lines.append('    </alerts>')
    lines.append('  </site>')

lines.append('</OWASPZAPReport>')

with open('$xml_file', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))

print('Converted: {} alerts written to XML'.format(
    sum(len(s.get('alerts',[])) for s in d.get('site',[]))))
" 2>&1
}

echo "=== Ensuring Product Type: $PRODUCT_TYPE ==="
PT_NAME_ENC=$(urlencode "$PRODUCT_TYPE")
PT_RESP=$(curl -sf "${DD_API}/product_types/?name=${PT_NAME_ENC}" \
  -H "$AUTH_H" -H "$CT_H")
PT_COUNT=$(json_field "count" "$PT_RESP")

if [ "${PT_COUNT:-0}" -gt 0 ]; then
  PT_ID=$(echo "$PT_RESP" | grep -o '"results":\[{"id":[0-9]*' | grep -o '[0-9]*$')
  echo "Found Product Type ID: $PT_ID"
else
  echo "Creating Product Type..."
  PT_CREATE=$(curl -sf -X POST "${DD_API}/product_types/" \
    -H "$AUTH_H" -H "$CT_H" \
    -d "{\"name\":\"${PRODUCT_TYPE}\",\"critical_product\":false,\"key_product\":false}")
  PT_ID=$(json_field "id" "$PT_CREATE")
  echo "Created Product Type ID: $PT_ID"
fi

echo "=== Ensuring Product: $PRODUCT ==="
PROD_NAME_ENC=$(urlencode "$PRODUCT")
PROD_RESP=$(curl -sf "${DD_API}/products/?name=${PROD_NAME_ENC}" \
  -H "$AUTH_H" -H "$CT_H")
PROD_COUNT=$(json_field "count" "$PROD_RESP")

if [ "${PROD_COUNT:-0}" -gt 0 ]; then
  PROD_ID=$(echo "$PROD_RESP" | grep -o '"results":\[{"id":[0-9]*' | grep -o '[0-9]*$')
  echo "Found Product ID: $PROD_ID"
else
  echo "Creating Product..."
  PROD_CREATE=$(curl -sf -X POST "${DD_API}/products/" \
    -H "$AUTH_H" -H "$CT_H" \
    -d "{\"name\":\"${PRODUCT}\",\"description\":\"Juice Shop security testing\",\"prod_type\":${PT_ID}}")
  PROD_ID=$(json_field "id" "$PROD_CREATE")
  echo "Created Product ID: $PROD_ID"
fi

echo "=== Ensuring Engagement: $ENGAGEMENT ==="
ENG_NAME_ENC=$(urlencode "$ENGAGEMENT")
ENG_RESP=$(curl -sf "${DD_API}/engagements/?name=${ENG_NAME_ENC}" \
  -H "$AUTH_H" -H "$CT_H")
ENG_COUNT=$(json_field "count" "$ENG_RESP")

if [ "${ENG_COUNT:-0}" -gt 0 ]; then
  ENG_ID=$(echo "$ENG_RESP" | grep -o '"results":\[{"id":[0-9]*' | grep -o '[0-9]*$')
  echo "Found Engagement ID: $ENG_ID"
else
  echo "Creating Engagement..."
  TODAY=$(date +%Y-%m-%d)
  ENG_CREATE=$(curl -sf -X POST "${DD_API}/engagements/" \
    -H "$AUTH_H" -H "$CT_H" \
    -d "{\"name\":\"${ENGAGEMENT}\",\"product\":${PROD_ID},\"engagement_type\":\"CI/CD\",\"status\":\"In Progress\",\"target_start\":\"${TODAY}\",\"target_end\":\"${TODAY}\"}")
  ENG_ID=$(json_field "id" "$ENG_CREATE")
  echo "Created Engagement ID: $ENG_ID"
fi

echo ""
echo "Context: Product Type=$PT_ID  Product=$PROD_ID  Engagement=$ENG_ID"
echo ""

import_scan() {
  local label="$1" file="$2" scan_type="$3"
  if [ ! -f "$file" ]; then
    echo "SKIP $label — file not found: $file"
    return
  fi
  local size
  size=$(wc -c < "$file" | tr -d ' ')
  if [ "${size}" -eq 0 ]; then
    echo "SKIP $label — file is empty (0 bytes): $file"
    return
  fi
  echo "=== Importing $label ($scan_type) — ${size} bytes ==="
  local out_file="labs/lab10/imports/${label// /-}-response.json"
  RESP=$(curl -s --max-time 180 -X POST "${DD_API}/import-scan/" \
    -H "Authorization: Token $DD_TOKEN" \
    -F "engagement=${ENG_ID}" \
    -F "scan_type=${scan_type}" \
    -F "file=@${file}" \
    -F "active=true" \
    -F "verified=false" \
    -F "close_old_findings=false" 2>&1 || true)
  echo "$RESP"
  echo "$RESP" > "$out_file"
  local test_id
  test_id=$(json_field "test" "$RESP")
  if [ -n "$test_id" ]; then
    echo "  -> Success! Test ID: $test_id"
  else
    echo "  -> WARNING: unexpected response (check $out_file)"
  fi
  echo ""
}

# ZAP: convert JSON -> XML first (DefectDojo ZAP Scan parser requires XML)
ZAP_JSON="labs/lab5/zap/zap-report-noauth.json"
ZAP_XML="labs/lab10/imports/zap-report-noauth.xml"
if [ -f "$ZAP_JSON" ]; then
  echo "=== Converting ZAP JSON -> XML ==="
  convert_zap_json_to_xml "$ZAP_JSON" "$ZAP_XML"
fi

import_scan "ZAP"     "$ZAP_XML"                                     "ZAP Scan"
import_scan "Semgrep" "labs/lab5/semgrep/semgrep-results.json"       "Semgrep JSON Report"
import_scan "Trivy"   "labs/lab4/trivy/trivy-vuln-detailed.json"     "Trivy Scan"
import_scan "Nuclei"  "labs/lab5/nuclei/nuclei-results.json"         "Nuclei Scan"
import_scan "Grype"   "labs/lab4/syft/grype-vuln-results.json"       "Anchore Grype"

echo "=== All done. Check labs/lab10/imports/ for raw responses. ==="
