#!/usr/bin/env bash
set -euo pipefail

COSIGN_BIN="$(pwd)/cosign2"
COSIGN_PASSWORD_VALUE="lab8-passphrase"

source labs/lab8/analysis/ref.env
mkdir -p labs/lab8/attest labs/lab8/analysis labs/lab4/syft

# Ensure Syft native SBOM exists (reuse from Lab 4 if present)
if [[ ! -f labs/lab4/syft/juice-shop-syft-native.json ]]; then
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$(pwd)":/tmp anchore/syft:latest \
    "$REF" -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json \
    | tee labs/lab8/attest/syft-generate-native.txt
else
  printf 'Reusing existing labs/lab4/syft/juice-shop-syft-native.json\n' | tee labs/lab8/attest/syft-reuse.txt
fi

# Convert Syft native SBOM to CycloneDX JSON
(docker run --rm \
  -v "$(pwd)/labs/lab4/syft":/in:ro \
  -v "$(pwd)/labs/lab8/attest":/out \
  anchore/syft:latest \
  convert /in/juice-shop-syft-native.json -o cyclonedx-json=/out/juice-shop.cdx.json) \
  | tee labs/lab8/attest/syft-convert-cdx.txt

# SBOM attestation (CycloneDX)
COSIGN_PASSWORD="$COSIGN_PASSWORD_VALUE" "$COSIGN_BIN" attest --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "$REF" | tee labs/lab8/attest/attest-sbom.txt

"$COSIGN_BIN" verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type cyclonedx \
  "$REF" | tee labs/lab8/attest/verify-sbom-attestation.txt

# Minimal provenance predicate
BUILD_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > labs/lab8/attest/provenance.json <<PROV
{
  "_type": "https://slsa.dev/provenance/v1",
  "buildType": "manual-local-demo",
  "builder": {"id": "student@local"},
  "invocation": {"parameters": {"image": "${REF}"}},
  "metadata": {"buildStartedOn": "${BUILD_TS}", "completeness": {"parameters": true}}
}
PROV

COSIGN_PASSWORD="$COSIGN_PASSWORD_VALUE" "$COSIGN_BIN" attest --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/provenance.json \
  --type slsaprovenance \
  "$REF" | tee labs/lab8/attest/attest-provenance.txt

"$COSIGN_BIN" verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type slsaprovenance \
  "$REF" | tee labs/lab8/attest/verify-provenance.txt

# Decode DSSE payloads and inspect with jq
jq -r 'if type=="array" then .[0].payload else .payload end' labs/lab8/attest/verify-sbom-attestation.txt \
  | base64 -d | jq . | tee labs/lab8/attest/sbom-attestation-payload.json >/dev/null

jq -r 'if type=="array" then .[0].payload else .payload end' labs/lab8/attest/verify-provenance.txt \
  | base64 -d | jq . | tee labs/lab8/attest/provenance-attestation-payload.json >/dev/null

jq '.predicateType, .predicate.metadata.buildStartedOn // empty' labs/lab8/attest/provenance-attestation-payload.json \
  | tee labs/lab8/analysis/provenance-payload-summary.txt
