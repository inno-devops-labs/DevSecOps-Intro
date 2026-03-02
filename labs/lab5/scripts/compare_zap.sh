#!/usr/bin/env bash
set -euo pipefail

NOAUTH_JSON="labs/lab5/zap/zap-report-noauth.json"
AUTH_JSON="labs/lab5/zap/zap-report-auth.json"

if [[ ! -f "$NOAUTH_JSON" || ! -f "$AUTH_JSON" ]]; then
  echo "Missing ZAP JSON reports. Expected:"
  echo "  $NOAUTH_JSON"
  echo "  $AUTH_JSON"
  exit 1
fi

pybin="python3"
if ! command -v "$pybin" >/dev/null 2>&1; then
  pybin="python"
fi
"$pybin" - <<'PY'
import json
from pathlib import Path

noauth_path = Path("labs/lab5/zap/zap-report-noauth.json")
auth_path = Path("labs/lab5/zap/zap-report-auth.json")

noauth = json.loads(noauth_path.read_text(encoding="utf-8"))
auth = json.loads(auth_path.read_text(encoding="utf-8"))

def collect_uris(doc):
    uris = []
    for site in doc.get("site", []):
        for alert in site.get("alerts", []):
            for inst in alert.get("instances", []):
                uri = inst.get("uri")
                if uri:
                    uris.append(uri)
    return sorted(set(uris))

noauth_sites = len(noauth.get("site", []))
auth_sites = len(auth.get("site", []))
noauth_urls = collect_uris(noauth)
auth_urls = collect_uris(auth)
noauth_admin = [u for u in noauth_urls if "/rest/admin/" in u]
auth_admin = [u for u in auth_urls if "/rest/admin/" in u]

print("=== ZAP Auth vs NoAuth Comparison ===")
print(f"NoAuth sites: {noauth_sites}")
print(f"Auth sites: {auth_sites}")
print(f"NoAuth discovered URLs (from alerts/instances): {len(noauth_urls)}")
print(f"Auth discovered URLs (from alerts/instances): {len(auth_urls)}")
print(f"NoAuth admin endpoint hits: {len(noauth_admin)}")
print(f"Auth admin endpoint hits: {len(auth_admin)}")
print()
print("Authenticated admin endpoint examples:")
for uri in auth_admin[:10]:
    print(uri)
PY
