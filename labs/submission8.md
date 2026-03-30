# Lab 8 Submission - Software Supply Chain Security: Signing, Verification, and Attestations

## Student / Context
- Name: `Danil Fishchenko`
- Branch: `feature/lab8`
- Work date: `2026-03-30 17:21:31 MSK`
- Repository root: `DevSecOps-Intro/`
- Target image: `bkimminich/juice-shop:v19.0.0`
- Host: `macOS (Darwin arm64)`
- Docker Engine: `29.2.1`
- Cosign: `v3.0.5`
- Local registry container: `lab08-registry`

Branch analysis before implementation:
- Local branches present at start: `feature/lab5`, `feature/lab6`, `feature/lab7`, `main`
- Remote branches present at start: `origin/feature/lab2` ... `origin/feature/lab7`, `origin/main`
- `feature/lab8` did not exist yet, so this lab was implemented in a new branch created from the current cumulative lab branch `feature/lab7`

Important compatibility note:
- The lab text uses `--tlog-upload=false`, but current `cosign v3.0.5` rejects that flag combination in the default signing flow.
- To keep the lab local/offline and still remain compatible with the current official Sigstore toolchain, I created a local signing config with no Fulcio/OIDC/Rekor/TSA services:

```bash
./labs/lab8/bin/cosign signing-config create \
  --no-default-fulcio \
  --no-default-oidc \
  --no-default-rekor \
  --no-default-tsa \
  --out labs/lab8/signing/local-signing-config.pb
```

- I then used `--signing-config labs/lab8/signing/local-signing-config.pb` for signing and attestations.
- The private key `labs/lab8/signing/cosign.key` and local Cosign binary are ignored via `labs/lab8/.gitignore`, so they are not accidentally committed.

Official references used:
- Sigstore install / usage docs: `https://docs.sigstore.dev/cosign/system_config/installation/`
- Sigstore self-managed key signing docs: `https://docs.sigstore.dev/cosign/key_management/signing_with_self-managed_keys/`
- Sigstore attestation docs: `https://docs.sigstore.dev/cosign/verifying/attestation/`
- Sigstore blob signing docs: `https://docs.sigstore.dev/cosign/signing/signing_with_blobs/`
- CNCF Distribution local registry docs: `https://distribution.github.io/distribution/about/configuration/`

## Task 1 - Local Registry, Signing, Verification, and Tamper Demonstration

### 1.1 Environment setup and commands used
```bash
docker pull bkimminich/juice-shop:v19.0.0

docker run -d --restart=always -p 5000:5000 \
  --name lab08-registry registry:3

docker tag bkimminich/juice-shop:v19.0.0 localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0

DIGEST=$(curl -sI \
  -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
  http://localhost:5000/v2/juice-shop/manifests/v19.0.0 \
  | tr -d '\r' | awk -F': ' '/Docker-Content-Digest/ {print $2}')
REF="localhost:5000/juice-shop@${DIGEST}"

COSIGN_PASSWORD='***' ./labs/lab8/bin/cosign generate-key-pair

COSIGN_PASSWORD='***' ./labs/lab8/bin/cosign sign --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/local-signing-config.pb \
  --key labs/lab8/signing/cosign.key \
  "$REF"

./labs/lab8/bin/cosign verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF"
```

Evidence files:
- `labs/lab8/registry/docker-pull-juice-shop.txt`
- `labs/lab8/registry/start-registry.txt`
- `labs/lab8/registry/docker-push-juice-shop.txt`
- `labs/lab8/signing/generate-key-pair.txt`
- `labs/lab8/signing/sign-image.txt`
- `labs/lab8/signing/verify-image.txt`
- `labs/lab8/analysis/ref.txt`

### 1.2 Signing and verification results
Original local-registry digest reference:
- `localhost:5000/juice-shop@sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5`

Observed verification result:
- Cosign successfully verified the signature with `labs/lab8/signing/cosign.pub`
- The verified subject digest in the claims is the same digest as the image reference
- Evidence is stored in `labs/lab8/signing/verify-image.txt`
- I re-ran the `cosign sign` step once at the end to refresh `labs/lab8/signing/sign-image.txt` with the command context and the actual Cosign stdout emitted on a successful sign. In this environment, Cosign prints only a minimal success line (`Signing artifact...`), so the final verification evidence shows two valid `https://sigstore.dev/cosign/sign/v1` claims for the same digest. This is expected for repeated signing of the same immutable subject with the same key.

Why the digest changed from Docker Hub's original multi-platform digest:
- The upstream image reference resolves to a multi-platform manifest list
- Pushing to the local registry from this host resulted in a single-platform OCI manifest for the locally available platform content
- That is why the local registry subject digest is `sha256:772d...`, not the Docker Hub list digest

### 1.3 Tamper demonstration
Commands used:
```bash
docker pull busybox:latest
docker tag busybox:latest localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0

DIGEST_AFTER=$(curl -sI \
  -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
  http://localhost:5000/v2/juice-shop/manifests/v19.0.0 \
  | tr -d '\r' | awk -F': ' '/Docker-Content-Digest/ {print $2}')
REF_AFTER="localhost:5000/juice-shop@${DIGEST_AFTER}"

./labs/lab8/bin/cosign verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF_AFTER"
```

Results:
- Tampered tag digest:
  - `localhost:5000/juice-shop@sha256:c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6`
- Verification of the tampered digest failed
- Saved exit code: `10`
- Saved error text:
  - `Error: no signatures found`
- Evidence files:
  - `labs/lab8/analysis/ref-after-tamper.txt`
  - `labs/lab8/signing/verify-after-tamper-failure.txt`
  - `labs/lab8/signing/verify-after-tamper-exit-code.txt`

Sanity check after tampering:
- Re-verifying the original digest `sha256:772d...` still succeeds
- Evidence: `labs/lab8/signing/verify-original-after-tamper.txt`

### 1.4 Analysis
How signing protects against tag tampering:
- A mutable tag like `localhost:5000/juice-shop:v19.0.0` can be repointed to completely different content.
- A Cosign signature is effectively bound to the subject manifest digest, not to the human-readable tag.
- After I overwrote the tag with `busybox`, the new digest had no matching signature, so verification failed immediately.
- The originally signed digest remained valid and verifiable, which is exactly the intended supply-chain property.

What "subject digest" means:
- The subject digest is the cryptographic identifier of the exact manifest being signed or attested.
- It is the immutable object identity that verification checks.
- In this lab, the meaningful trust anchor is `sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5`, not the mutable tag `v19.0.0`.

## Task 2 - Attestations: SBOM and Provenance

### 2.1 SBOM generation and conversion
Lab 4 SBOM artifacts were not present in the current branch workspace, so I regenerated the Syft-native SBOM locally under `labs/lab8/attest/` and then converted it to CycloneDX JSON.

Commands used:
```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp \
  anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 \
  -o syft-json=/tmp/labs/lab8/attest/juice-shop-syft-native.json

docker run --rm \
  -v "$(pwd)/labs/lab8/attest":/work \
  anchore/syft:latest \
  convert /work/juice-shop-syft-native.json -o cyclonedx-json=/work/juice-shop.cdx.json
```

Observed facts:
- Syft version in the decoded attestation payload metadata: `1.42.3`
- CycloneDX component count in the verified payload: `3532`

Evidence files:
- `labs/lab8/attest/generate-syft-native.log`
- `labs/lab8/attest/convert-sbom.log`
- `labs/lab8/attest/juice-shop-syft-native.json`
- `labs/lab8/attest/juice-shop.cdx.json`

### 2.2 SBOM attestation
Commands used:
```bash
COSIGN_PASSWORD='***' ./labs/lab8/bin/cosign attest --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/local-signing-config.pb \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "$REF"

./labs/lab8/bin/cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type cyclonedx \
  "$REF"
```

Verified payload summary:
- Predicate type: `https://cyclonedx.org/bom`
- Subject digest: `sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5`
- Component count: `3532`

Payload inspection:
```bash
jq -r '.payload' labs/lab8/attest/verify-sbom-attestation.txt \
  | openssl base64 -d -A | jq '.'
```

Evidence files:
- `labs/lab8/attest/sign-sbom-attestation.txt`
- `labs/lab8/attest/verify-sbom-attestation.txt`
- `labs/lab8/analysis/sbom-attestation-payload.json`
- `labs/lab8/analysis/sbom-attestation-summary.json`

What the SBOM attestation contains:
- The signed subject binding to the specific Juice Shop digest
- CycloneDX metadata about the container artifact
- The package inventory itself, including a large dependency/component set
- Tool metadata showing the SBOM was produced by Syft

### 2.3 Provenance attestation
Predicate creation:
```bash
{
  "_type": "https://slsa.dev/provenance/v1",
  "buildType": "manual-local-demo",
  "builder": {"id": "student@local"},
  "invocation": {"parameters": {"image": "$REF"}},
  "metadata": {"buildStartedOn": "<RFC3339 UTC timestamp>", "completeness": {"parameters": true}}
}
```

Commands used:
```bash
COSIGN_PASSWORD='***' ./labs/lab8/bin/cosign attest --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/local-signing-config.pb \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/provenance.json \
  --type slsaprovenance \
  "$REF"

./labs/lab8/bin/cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type slsaprovenance \
  "$REF"
```

Verified payload summary:
- Observed predicate type in the verified envelope: `https://slsa.dev/provenance/v0.2`
- Subject digest: `sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5`
- `buildType`: `manual-local-demo`
- `builder.id`: `student@local`
- `buildStartedOn`: `2026-03-30T14:16:27Z`

Payload inspection:
```bash
jq -r '.payload' labs/lab8/attest/verify-provenance.txt \
  | openssl base64 -d -A | jq '.'
```

Evidence files:
- `labs/lab8/attest/provenance.json`
- `labs/lab8/attest/sign-provenance-attestation.txt`
- `labs/lab8/attest/verify-provenance.txt`
- `labs/lab8/analysis/provenance-attestation-payload.json`
- `labs/lab8/analysis/provenance-attestation-summary.json`

What provenance provides for supply chain security:
- It records who/what produced the artifact context
- It captures build metadata such as build type and timestamp
- It documents invocation parameters relevant to the build
- It improves traceability, reproducibility analysis, and post-incident investigation

### 2.4 Analysis - Signatures vs Attestations
How attestations differ from signatures:
- A signature mainly answers: "Was this exact subject digest signed by a trusted key?"
- An attestation answers: "What signed metadata statement is attached to this exact subject digest?"
- In practice, signatures protect integrity/authenticity of the artifact identity, while attestations add verifiable context about that artifact.

Why both matter:
- Signature without metadata proves authenticity but says little about contents or build process.
- Attestation without trusted verification is just an unsigned claim.
- Together they let a pipeline answer both identity and context questions.

## Task 3 - Artifact (Blob/Tarball) Signing

### 3.1 Commands used
```bash
echo "sample content $(date -u +%Y-%m-%dT%H:%M:%SZ)" > labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

COSIGN_PASSWORD='***' ./labs/lab8/bin/cosign sign-blob --yes \
  --key labs/lab8/signing/cosign.key \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  --signing-config labs/lab8/signing/local-signing-config.pb \
  labs/lab8/artifacts/sample.tar.gz

./labs/lab8/bin/cosign verify-blob \
  --key labs/lab8/signing/cosign.pub \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  --insecure-ignore-tlog \
  labs/lab8/artifacts/sample.tar.gz
```

Results:
- Blob bundle created successfully: `labs/lab8/artifacts/sample.tar.gz.bundle`
- Verification result: `Verified OK`

Evidence files:
- `labs/lab8/artifacts/sample.txt`
- `labs/lab8/artifacts/sample.tar.gz`
- `labs/lab8/artifacts/sample.tar.gz.bundle`
- `labs/lab8/artifacts/sign-blob.txt`
- `labs/lab8/artifacts/verify-blob.txt`

Use cases for signing non-container artifacts:
- Release binaries and CLI tools
- Tarballs / source archives
- Configuration bundles and policy packs
- SBOM exports and compliance evidence packages

How blob signing differs from container image signing:
- Blob signing works on a local file directly and produces a detached verification bundle/signature material.
- Image signing stores the signature material in an OCI registry, bound to an image manifest digest.
- Blob signing is useful when the artifact is not an OCI image at all.

## Conclusions
The lab objective was achieved:
- The Juice Shop image was pushed to a local registry, signed, and verified with a local Cosign key pair.
- Tag tampering was demonstrated correctly: the new digest failed verification, while the original digest still verified.
- Both SBOM and provenance attestations were attached to the original signed digest, verified, and decoded with `jq`.
- A non-container artifact tarball was signed and verified successfully.

The main practical lesson is that trust must follow immutable digests and signed statements, not mutable tags or manual assumptions about artifact contents. The tamper test demonstrated this very clearly.

## Files Delivered
- `labs/submission8.md`
- `labs/lab8/.gitignore`
- `labs/lab8/analysis/*`
- `labs/lab8/registry/*`
- `labs/lab8/signing/cosign.pub`
- `labs/lab8/signing/generate-key-pair.txt`
- `labs/lab8/signing/local-signing-config.pb`
- `labs/lab8/signing/sign-image.txt`
- `labs/lab8/signing/verify-image.txt`
- `labs/lab8/signing/verify-after-tamper-failure.txt`
- `labs/lab8/signing/verify-after-tamper-exit-code.txt`
- `labs/lab8/signing/verify-original-after-tamper.txt`
- `labs/lab8/attest/*`
- `labs/lab8/artifacts/*`
