# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Local Registry, Signing & Verification

### Environment Setup

The Juice Shop image (`bkimminich/juice-shop:v19.0.0`) was pulled from Docker Hub and pushed to a locally running registry on port 5000. The local digest differs from the upstream Docker Hub digest because the hub exposes a multi-platform manifest list, while pushing to the local registry produced a single-platform OCI manifest for the current host architecture

Commands used:
```
# Pull target image
docker pull bkimminich/juice-shop:v19.0.0

# Start local registry
docker run -d --restart=always -p 5000:5000 --name lab08-registry registry:3

# Tag and push to local registry
docker tag bkimminich/juice-shop:v19.0.0 localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0

# Resolve digest reference from local registry
DIGEST=$(curl -sI \
  -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
  http://localhost:5000/v2/juice-shop/manifests/v19.0.0 \
  | tr -d '\r' | awk -F': ' '/Docker-Content-Digest/ {print $2}')
REF="localhost:5000/juice-shop@${DIGEST}"
echo "Using digest ref: $REF" | tee labs/lab8/analysis/ref.txt
```

Resulting ref:
```
Using digest ref: localhost:5000/juice-shop@sha256:11f85134f388cff5f4c66f9bb4c5942249c1f6f7eb8b3889948d953487b5f7a8
```

### Signing & Verification

A local key pair was generated with `Cosign`. The image was then signed against the digest reference using the private key, and the resulting signature was stored in the OCI registry alongside the image. Verification was performed using the public key and confirmed that the subject digest matched the signed claims.To avoid interaction with Fulcio, Rekor, or any other Sigstore transparency services, a local signing config was applied:

```bash
cosign sign --key cosign.key --signing-config local-signing-config.pb
cosign verify --key cosign.pub --insecure-ignore-tlog
```

### Tamper Demonstration
To demonstrate tag mutability, the v19.0.0 tag was deliberately overwritten by pushing a completely different image (busybox) under the same name. A new digest was retrieved for the tampered tag and subjected to the same verification command

Result: 

Verification of the tampered digest failed immediately with error **no signatures found**. The original digest, however, continued to verify successfully — confirming that Cosign's trust anchor is the immutable digest, not the mutable tag

### Analysis
How signing protects against tag tampering:

Docker tags are human-readable pointers that can be freely reassigned to any image. Cosign addresses this by binding the cryptographic signature to the image's SHA256 digest rather than its tag. During verification, the public key is used to check whether the signature matches the digest of the presented image. If the tag has been redirected to different content, the digest changes, the signature no longer matches, and verification fails — effectively preventing image substitution attacks in the supply chain

### What "subject digest" means
The subject digest is the SHA256 hash of the specific image manifest that was signed. It serves as the immutable identity of the artifact, independent of any tags. In this lab, the meaningful trust anchor is `sha256:772d...`, not the tag `v19.0.0`

## Task 2 — Attestations: SBOM & Provenance
SBOM Generation and Attestation
Since Lab 4 artifacts were not available in the current branch, a fresh Syft-native SBOM was generated for the Juice Shop image and converted to CycloneDX JSON format:
```bash
# Generate Syft-native SBOM
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp \
  anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 \
  -o syft-json=/tmp/labs/lab8/attest/juice-shop-syft-native.json

# Convert to CycloneDX JSON
docker run --rm \
  -v "$(pwd)/labs/lab8/attest":/work \
  anchore/syft:latest \
  convert /work/juice-shop-syft-native.json -o cyclonedx-json=/work/juice-shop.cdx.json
```
The resulting file was then attached to the image as a signed attestation and verified:

```bash
# Attach SBOM attestation
COSIGN_PASSWORD='***' ./labs/lab8/bin/cosign attest --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/local-signing-config.pb \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "$REF"

# Verify SBOM attestation
./labs/lab8/bin/cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type cyclonedx \
  "$REF" | tee labs/lab8/attest/verify-sbom-attestation.txt

# Inspect the attestation payload
jq -r '.payload' labs/lab8/attest/verify-sbom-attestation.txt \
  | openssl base64 -d -A | jq '.'
```
Decoding the verified payload revealed 3,532 components catalogued by Syft v1.42.3, including packages, libraries, dependency metadata, license information, and source hashes.
Provenance Attestation
A minimal SLSA provenance predicate was authored manually and attached as a second attestation to the same digest:

```bash
# Create provenance predicate
BUILD_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > labs/lab8/attest/provenance.json << EOF
{
  "_type": "https://slsa.dev/provenance/v1",
  "buildType": "manual-local-demo",
  "builder": {"id": "student@local"},
  "invocation": {"parameters": {"image": "${REF}"}},
  "metadata": {"buildStartedOn": "${BUILD_TS}", "completeness": {"parameters": true}}
}
EOF

# Attach provenance attestation
COSIGN_PASSWORD='***' ./labs/lab8/bin/cosign attest --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/local-signing-config.pb \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/provenance.json \
  --type slsaprovenance \
  "$REF"

# Verify provenance attestation
./labs/lab8/bin/cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type slsaprovenance \
  "$REF" | tee labs/lab8/attest/verify-provenance.txt

# Inspect the attestation payload
jq -r '.payload' labs/lab8/attest/verify-provenance.txt \
  | openssl base64 -d -A | jq '.'
```
The verified envelope reported predicate type https://slsa.dev/provenance/v0.2, builder ID `student@local`, build type manual-local-demo, and build timestamp `2026-03-30T14:16:27Z`
### Analysis
#### How attestations differ from signatures
A signature answers one question: was this exact digest signed by a trusted key? An attestation answers a richer question: what verified metadata statement is attached to this digest? In practice, signatures protect the integrity and authenticity of the artifact identity, while attestations supply verifiable context about how, when, and by whom the artifact was produced

| | Signature | Attestation |
|---|---|---|
| Purpose | Verify integrity & authenticity | Attach metadata about the artifact |
| Bound to | Image digest | Image digest |
| Content | Cryptographic signature | Signed JSON predicate (SBOM, provenance, etc.) |
| Use case | Trust verification | Supply chain transparency |

### What the SBOM attestation contains
The SBOM attestation packages a full CycloneDX inventory of every component found in the image — packages, libraries, transitive dependencies, versions, licenses, and source hashes — alongside tool metadata identifying Syft as the generator. This enables downstream consumers to scan for known vulnerabilities, audit licenses, and identify supply chain risks without re-analysing the image themselves

### Why provenance attestation matters
Provenance records who built the artifact, under what conditions, and with what inputs. It improves traceability for post-incident investigation, supports reproducibility analysis, and provides evidence that the image originated from a trusted build environment rather than an ad-hoc or compromised process

## Task 3 — Artifact (Blob) Signing
### Signing and Verification
A sample tarball was created and signed using Cosign's blob signing flow. Unlike container image signing, the signature material is stored in a local bundle file rather than an OCI registry:
```bash
# Create sample artifact
echo "sample content $(date -u +%Y-%m-%dT%H:%M:%SZ)" > labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

# Sign the blob
COSIGN_PASSWORD='***' ./labs/lab8/bin/cosign sign-blob --yes \
  --key labs/lab8/signing/cosign.key \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  --signing-config labs/lab8/signing/local-signing-config.pb \
  labs/lab8/artifacts/sample.tar.gz

# Verify the blob
./labs/lab8/bin/cosign verify-blob \
  --key labs/lab8/signing/cosign.pub \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  --insecure-ignore-tlog \
  labs/lab8/artifacts/sample.tar.gz | tee labs/lab8/artifacts/verify-blob.txt
```

Verification returned Verified OK, confirming the tarball's integrity and the signature's validity

### Analysis
#### Use cases for signing non-container artifacts
Blob signing is applicable to any distributable artifact that travels outside an OCI registry:
- Release binaries and CLI tools distributed to end users
- Source archives and dependency tarballs
- Configuration bundles, Terraform plans, and policy packs
- SBOM exports and compliance evidence packages
- CI/CD pipeline outputs

### How blob signing differs from container image signing
The key difference is that blob signing operates on arbitrary files directly and produces a detached bundle, while image signing is registry-native and leverages OCI manifest digests as the trust anchor

| | Container Image Signing | Blob Signing |
|---|---|---|
| Target | OCI container image | Any file (binary, tarball, config, etc.) |
| Signature storage | OCI registry (alongside image) | Local or distributed bundle file |
| Bound to | Image manifest digest | File content hash |
| Use case | Container supply chain security | General artifact integrity |

### Conclusion
This lab demonstrated a complete set of supply chain security primitives using Cosign and local infrastructure. Tag tampering was shown to be trivially easy — and equally trivially detectable when digest-based signing is in place. Attestations extended that trust model beyond simple authenticity checks, attaching verifiable SBOM and provenance metadata to the same immutable digest. Finally, blob signing proved that the same cryptographic guarantees can be applied to any artifact, not just container images.
The core practical lesson is that trust must follow immutable digests and signed statements, not mutable tags or manual assumptions about artifact contents