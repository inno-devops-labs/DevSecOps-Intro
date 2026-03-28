#!/bin/zsh
set -euo pipefail

mkdir -p labs/lab8/{registry,signing,attest,analysis,artifacts}

REG_HOST="localhost:5001"
REF_REPO="${REG_HOST}/juice-shop"
COSIGN_PASSWORD_VALUE="lab8-local-passphrase"

cosign version > labs/lab8/analysis/cosign-version.txt
docker pull bkimminich/juice-shop:v19.0.0 > labs/lab8/registry/pull-image.txt

if docker ps -a --filter name='^/registry$' --format '{{.Names}}' | grep -qx registry; then
  docker start registry > labs/lab8/registry/start-registry.txt 2>/dev/null || true
else
  docker run -d --restart=always -p 5001:5000 --name registry registry:3 > labs/lab8/registry/start-registry.txt
fi

docker tag bkimminich/juice-shop:v19.0.0 "${REF_REPO}:v19.0.0"
docker push "${REF_REPO}:v19.0.0" > labs/lab8/registry/push-local.txt

DIGEST="$(curl -sI \
  -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
  "http://${REG_HOST}/v2/juice-shop/manifests/v19.0.0" \
  | tr -d '\r' | awk -F': ' '/Docker-Content-Digest/ {print $2}')"
REF="${REF_REPO}@${DIGEST}"
printf 'Using digest ref: %s\n' "${REF}" | tee labs/lab8/analysis/ref.txt > /dev/null

if [[ ! -f labs/lab8/signing/cosign.key || ! -f labs/lab8/signing/cosign.pub ]]; then
  COSIGN_PASSWORD="${COSIGN_PASSWORD_VALUE}" cosign generate-key-pair \
    --output-key-prefix labs/lab8/signing/cosign > labs/lab8/signing/generate-key-pair.txt 2>&1
else
  printf 'Existing key pair reused.\n' > labs/lab8/signing/generate-key-pair.txt
fi

COSIGN_PASSWORD="${COSIGN_PASSWORD_VALUE}" cosign sign --yes \
  --use-signing-config=false \
  --allow-http-registry \
  --allow-insecure-registry \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  "${REF}" > labs/lab8/signing/sign.txt 2>&1
cosign verify \
  --allow-http-registry \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "${REF}" > labs/lab8/signing/verify.txt 2>&1

docker pull busybox:latest > labs/lab8/analysis/tamper-pull-busybox.txt
docker tag busybox:latest "${REF_REPO}:v19.0.0"
docker push "${REF_REPO}:v19.0.0" > labs/lab8/analysis/tamper-push.txt

DIGEST_AFTER="$(curl -sI \
  -H "Accept: application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
  "http://${REG_HOST}/v2/juice-shop/manifests/v19.0.0" \
  | tr -d '\r' | awk -F': ' '/Docker-Content-Digest/ {print $2}')"
REF_AFTER="${REF_REPO}@${DIGEST_AFTER}"
printf 'After tamper digest ref: %s\n' "${REF_AFTER}" | tee labs/lab8/analysis/ref-after-tamper.txt > /dev/null

set +e
cosign verify \
  --allow-http-registry \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "${REF_AFTER}" > labs/lab8/signing/verify-after-tamper.txt 2>&1
TAMPER_STATUS=$?
set -e

printf 'tamper_verify_exit_code=%s\n' "${TAMPER_STATUS}" > labs/lab8/analysis/tamper-status.txt

cosign verify \
  --allow-http-registry \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "${REF}" > labs/lab8/signing/verify-original-after-tamper.txt 2>&1

echo "task1_done"
