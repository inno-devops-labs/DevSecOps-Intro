#!/usr/bin/env bash
set -euo pipefail

COSIGN_BIN="$(pwd)/cosign2"
COSIGN_PASSWORD_VALUE="lab8-passphrase"

mkdir -p labs/lab8/{registry,signing,analysis}

# 1) Pull target image
(docker pull bkimminich/juice-shop:v19.0.0) | tee labs/lab8/registry/docker-pull-juice-shop.txt

# 2) Start/restart local registry container
if docker ps -a --format '{{.Names}}' | grep -qx 'registry'; then
  docker rm -f registry | tee labs/lab8/registry/registry-rm.txt
fi
(docker run -d --restart=always -p 5000:5000 --name registry registry:3) | tee labs/lab8/registry/registry-run.txt

# 3) Tag and push image to local registry
(docker tag bkimminich/juice-shop:v19.0.0 localhost:5000/juice-shop:v19.0.0) | tee labs/lab8/registry/docker-tag-juice-shop.txt
(docker push localhost:5000/juice-shop:v19.0.0) | tee labs/lab8/registry/docker-push-juice-shop.txt

# 4) Resolve digest and build immutable reference
DIGEST=$(curl -sI \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  http://localhost:5000/v2/juice-shop/manifests/v19.0.0 \
  | tr -d '\r' | awk -F': ' '/Docker-Content-Digest/ {print $2}')
REF="localhost:5000/juice-shop@${DIGEST}"
printf '%s\n' "Using digest ref: $REF" | tee labs/lab8/analysis/ref.txt
printf 'REF=%s\n' "$REF" > labs/lab8/analysis/ref.env

# 5) Generate cosign key pair
rm -f labs/lab8/signing/cosign.key labs/lab8/signing/cosign.pub
COSIGN_PASSWORD="$COSIGN_PASSWORD_VALUE" "$COSIGN_BIN" generate-key-pair --output-key-prefix labs/lab8/signing/cosign \
  | tee labs/lab8/signing/generate-key-pair.txt

# 6) Sign and verify
COSIGN_PASSWORD="$COSIGN_PASSWORD_VALUE" "$COSIGN_BIN" sign --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  "$REF" | tee labs/lab8/signing/sign-image.txt

"$COSIGN_BIN" verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF" | tee labs/lab8/signing/verify-original.txt

# 7) Tamper demonstration
(docker pull busybox:latest) | tee labs/lab8/registry/docker-pull-busybox.txt
(docker tag busybox:latest localhost:5000/juice-shop:v19.0.0) | tee labs/lab8/registry/docker-tag-busybox-overwrite.txt
(docker push localhost:5000/juice-shop:v19.0.0) | tee labs/lab8/registry/docker-push-busybox-overwrite.txt

DIGEST_AFTER=$(curl -sI \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  http://localhost:5000/v2/juice-shop/manifests/v19.0.0 \
  | tr -d '\r' | awk -F': ' '/Docker-Content-Digest/ {print $2}')
REF_AFTER="localhost:5000/juice-shop@${DIGEST_AFTER}"
printf '%s\n' "After tamper digest ref: $REF_AFTER" | tee labs/lab8/analysis/ref-after-tamper.txt
printf 'REF_AFTER=%s\n' "$REF_AFTER" > labs/lab8/analysis/ref-after-tamper.env

set +e
"$COSIGN_BIN" verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF_AFTER" > labs/lab8/signing/verify-after-tamper.txt 2>&1
TAMPER_RC=$?
set -e
printf 'verify_after_tamper_exit_code=%s\n' "$TAMPER_RC" | tee labs/lab8/signing/verify-after-tamper-exit.txt

"$COSIGN_BIN" verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF" | tee labs/lab8/signing/verify-original-post-tamper.txt
