#!/bin/zsh
set -euo pipefail

mkdir -p labs/lab8/artifacts

COSIGN_PASSWORD_VALUE="lab8-local-passphrase"

echo "sample content $(date -u +%Y-%m-%dT%H:%M:%SZ)" > labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

COSIGN_PASSWORD="${COSIGN_PASSWORD_VALUE}" cosign sign-blob \
  --yes \
  --use-signing-config=false \
  --key labs/lab8/signing/cosign.key \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz \
  > labs/lab8/artifacts/sign-blob.txt 2>&1

cosign verify-blob \
  --key labs/lab8/signing/cosign.pub \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz \
  > labs/lab8/artifacts/verify-blob.txt 2>&1

echo "task3_done"
