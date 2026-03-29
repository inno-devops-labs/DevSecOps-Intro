# Lab 8 Submission — Software Supply Chain Security: Signing, Verification, and Attestations

**Student:** Sarmat  
**Date:** March 29, 2026

---

## Task 1 — Local Registry, Signing & Verification

### Setup

Started a local registry on port 5001 (port 5000 was occupied by macOS Control Center):

```bash
docker run -d --restart=always -p 5001:5000 --name registry registry:3
docker tag bkimminich/juice-shop:v19.0.0 localhost:5001/juice-shop:v19.0.0
docker push localhost:5001/juice-shop:v19.0.0
```

Resolved digest reference:
```
localhost:5001/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7
```

### Key Generation

```bash
COSIGN_PASSWORD=<your-passphrase> cosign generate-key-pair --output-key-prefix labs/lab8/signing/cosign
# Private key written to labs/lab8/signing/cosign.key
# Public key written to labs/lab8/signing/cosign.pub
```

### Signing

```bash
COSIGN_PASSWORD=<your-passphrase> cosign sign --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/signing-config-notlog.json \
  --key labs/lab8/signing/cosign.key \
  "$REF"
# Output: Signing artifact...
```

### Verification

```
Verification for localhost:5001/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5001/juice-shop@sha256:872efcc..."},"image":{"docker-manifest-digest":"sha256:872efcc..."},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demonstration

Replaced the image tag with `busybox:latest`:

```bash
docker tag busybox:latest localhost:5001/juice-shop:v19.0.0
docker push localhost:5001/juice-shop:v19.0.0
# New digest: sha256:50a3a2fef78c92dee45a3a9b72af5bdcbff6476e685cef49d97f286b6ce6f14a
```

Verification of tampered image **FAILED**:
```
Error: no signatures found
```

Verification of original digest still **PASSED** — proving the original image is intact.

### How Signing Protects Against Tag Tampering

A Docker tag (like `v19.0.0`) is a mutable pointer — anyone with push access can overwrite it with a different image. Cosign signs the **digest** (SHA256 hash of the manifest), not the tag. The digest is immutable and uniquely identifies the exact image content.

When you verify by digest, Cosign checks that the cryptographic signature matches that specific content hash. If an attacker replaces the tag with a different image, the new digest has no valid signature, and verification fails immediately.

**"Subject digest"** is the SHA256 hash of the image manifest that was signed. It's embedded in the signature payload and acts as the cryptographic binding between the signature and the exact image content.

---

## Task 2 — Attestations: SBOM & Provenance

### SBOM Generation

Generated CycloneDX SBOM using Syft directly from the local registry image:

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  "$REF" -o cyclonedx-json=/tmp/labs/lab8/attest/juice-shop.cdx.json
```

Result: 2.1MB CycloneDX JSON with full dependency tree.

### SBOM Attestation

```bash
cosign attest --yes --allow-insecure-registry \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx "$REF"
```

Verification confirmed with `cosign verify-attestation --type cyclonedx`.

### Provenance Attestation

Created a minimal SLSA Provenance v1 predicate:

```json
{
  "_type": "https://slsa.dev/provenance/v1",
  "buildType": "manual-local-demo",
  "builder": {"id": "student@local"},
  "invocation": {"parameters": {"image": "localhost:5001/juice-shop@sha256:872efcc..."}},
  "metadata": {"buildStartedOn": "2026-03-29T20:46:13Z", "completeness": {"parameters": true}}
}
```

Verified with `cosign verify-attestation --type slsaprovenance`.

### How Attestations Differ from Signatures

| | Signature | Attestation |
|---|---|---|
| What it proves | "I signed this image" | "This image has property X" |
| Content | Cryptographic signature only | Signed envelope with structured payload |
| Examples | `cosign sign` | SBOM, provenance, test results, vulnerability scan |
| Format | Simple signature | in-toto envelope with predicate |

A **signature** proves authenticity — who signed the image and that it hasn't been tampered with.

An **attestation** is a signed statement about the image — it carries a payload (like an SBOM or build provenance) wrapped in a cryptographic envelope. You can verify both who made the claim AND what the claim says.

### What the SBOM Attestation Contains

The CycloneDX SBOM attestation payload (base64-decoded) contains:
- Full list of all packages in the image (npm packages, OS packages)
- Package versions, licenses, and hashes
- Dependency relationships between components
- Image metadata (name, version, labels)
- Tool information (Syft version used to generate it)

This enables consumers to verify exactly what software is in the image without running it.

### What Provenance Attestations Provide

Provenance answers "where did this image come from?":
- Which build system produced it
- What source code was used (commit hash)
- When it was built
- What parameters were passed to the build

In production, provenance from a trusted CI/CD system (GitHub Actions, Tekton) lets you enforce policies like "only deploy images built from the main branch by the official pipeline."

---

## Task 3 — Artifact (Blob/Tarball) Signing

### Signing

```bash
echo "sample content $(date -u)" > labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

cosign sign-blob \
  --key labs/lab8/signing/cosign.key \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz
# Output: Wrote bundle to file labs/lab8/artifacts/sample.tar.gz.bundle
```

### Verification

```bash
cosign verify-blob \
  --key labs/lab8/signing/cosign.pub \
  --insecure-ignore-tlog \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz
# Output: Verified OK
```

### Use Cases for Signing Non-Container Artifacts

1. **Release binaries** — Sign compiled executables so users can verify they downloaded the official build, not a tampered version from a mirror
2. **Configuration files** — Sign Kubernetes manifests, Helm charts, or Terraform plans to ensure they haven't been modified between approval and deployment
3. **SBOM files** — Sign the SBOM itself so consumers can trust the bill of materials
4. **ML models** — Sign trained model files to ensure integrity in ML pipelines
5. **Database migrations** — Sign migration scripts to prevent unauthorized schema changes

### How Blob Signing Differs from Container Image Signing

| | Container Image Signing | Blob Signing |
|---|---|---|
| Storage | Signature stored in OCI registry alongside image | Signature stored in a bundle file or detached |
| Reference | Signs the image manifest digest | Signs the file content hash (SHA256) |
| Distribution | Registry handles signature discovery | Bundle file must be distributed alongside artifact |
| Verification | `cosign verify` with registry reference | `cosign verify-blob` with local file + bundle |
| Attestations | Supported via OCI referrers API | Limited support |

Container image signing leverages the OCI registry as a distribution mechanism for signatures. Blob signing is more flexible but requires manual management of the bundle/signature files alongside the artifact.
