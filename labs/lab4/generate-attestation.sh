#!/bin/bash
set -euo pipefail

CDX="labs/lab4/juice-shop.cdx.json"
OUT="labs/lab4/juice-shop-attestation.json"
IMAGE="bkimminich/juice-shop:v20.0.0"

DIGEST=$(docker inspect "$IMAGE" --format '{{index .RepoDigests 0}}')
if [ -z "$DIGEST" ]; then
  echo "RepoDigests empty — run: docker pull $IMAGE"
  exit 1
fi

SHA256="${DIGEST#*@}"

jq -n \
  --arg name "$IMAGE" \
  --arg sha "$SHA256" \
  --slurpfile predicate "$CDX" \
  '{
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [
      {
        "name": $name,
        "digest": {
          "sha256": ($sha | ltrimstr("sha256:"))
        }
      }
    ],
    "predicateType": "https://cyclonedx.org/bom/v1.5",
    "predicate": $predicate[0]
  }' > "$OUT"

echo "Wrote $OUT"
jq '._type, .subject[0].digest.sha256, .predicateType' "$OUT"
