#!/bin/zsh
set -euo pipefail

mkdir -p labs/lab8/attest labs/lab8/analysis

REF="$(sed 's/^Using digest ref: //' labs/lab8/analysis/ref.txt)"
COSIGN_PASSWORD_VALUE="lab8-local-passphrase"

docker run --rm \
  -v "$(pwd)/labs/lab4/syft":/in:ro \
  -v "$(pwd)/labs/lab8/attest":/out \
  anchore/syft:latest \
  convert /in/juice-shop-syft-native.json -o cyclonedx-json=/out/juice-shop.cdx.json \
  > labs/lab8/attest/convert-sbom.txt 2>&1

BUILD_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > labs/lab8/attest/provenance.json <<EOF
{
  "_type": "https://slsa.dev/provenance/v1",
  "buildType": "manual-local-demo",
  "builder": {"id": "student@local"},
  "invocation": {"parameters": {"image": "${REF}"}},
  "metadata": {"buildStartedOn": "${BUILD_TS}", "completeness": {"parameters": true}}
}
EOF

COSIGN_PASSWORD="${COSIGN_PASSWORD_VALUE}" cosign attest --yes \
  --replace \
  --use-signing-config=false \
  --allow-http-registry \
  --allow-insecure-registry \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "${REF}" > labs/lab8/attest/attest-sbom.txt 2>&1

cosign verify-attestation \
  --allow-http-registry \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type cyclonedx \
  "${REF}" > labs/lab8/attest/verify-sbom-attestation.txt 2>&1

python3 - <<'PY'
import base64
import json
from pathlib import Path

src = Path("labs/lab8/attest/verify-sbom-attestation.txt")
lines = [line for line in src.read_text().splitlines() if line.strip()]
json_line = next(line for line in reversed(lines) if line.lstrip().startswith("{") or line.lstrip().startswith("["))
data = json.loads(json_line)
payload = data["payload"] if isinstance(data, dict) else data[0]["payload"]
decoded = json.loads(base64.b64decode(payload).decode())
Path("labs/lab8/attest/sbom-attestation-payload.json").write_text(json.dumps(decoded, indent=2) + "\n")
PY

COSIGN_PASSWORD="${COSIGN_PASSWORD_VALUE}" cosign attest --yes \
  --replace \
  --use-signing-config=false \
  --allow-http-registry \
  --allow-insecure-registry \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/provenance.json \
  --type slsaprovenance \
  "${REF}" > labs/lab8/attest/attest-provenance.txt 2>&1

cosign verify-attestation \
  --allow-http-registry \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type slsaprovenance \
  "${REF}" > labs/lab8/attest/verify-provenance.txt 2>&1

python3 - <<'PY'
import base64
import json
from pathlib import Path

src = Path("labs/lab8/attest/verify-provenance.txt")
lines = [line for line in src.read_text().splitlines() if line.strip()]
json_line = next(line for line in reversed(lines) if line.lstrip().startswith("{") or line.lstrip().startswith("["))
data = json.loads(json_line)
payload = data["payload"] if isinstance(data, dict) else data[0]["payload"]
decoded = json.loads(base64.b64decode(payload).decode())
Path("labs/lab8/attest/provenance-attestation-payload.json").write_text(json.dumps(decoded, indent=2) + "\n")
PY

echo "task2_done"
