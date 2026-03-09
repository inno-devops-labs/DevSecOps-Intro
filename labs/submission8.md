# Lab 8 Submission — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Local Registry, Signing & Verification

### 1.1 Pull and Push to Local Registry

The target image was pulled and pushed to a local Distribution v3 registry:

```bash
docker pull bkimminich/juice-shop:v19.0.0

# Start local registry
docker run -d --restart=always -p 5000:5000 --name registry registry:3

# Tag and push
docker tag bkimminich/juice-shop:v19.0.0 localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

A digest reference was resolved from the local registry for all subsequent operations:

```bash
DIGEST=$(curl -sI \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  http://localhost:5000/v2/juice-shop/manifests/v19.0.0 \
  | tr -d '\r' | awk -F': ' '/Docker-Content-Digest/ {print $2}')
REF="localhost:5000/juice-shop@${DIGEST}"
echo "Using digest ref: $REF" | tee labs/lab8/analysis/ref.txt
```

**Result:**
```
Using digest ref: localhost:5000/juice-shop@sha256:9c3f1a2e5d...
```

**Why use a digest reference instead of a tag?**

Tags are mutable — anyone with push access can overwrite `v19.0.0` with a completely different image. A digest (`sha256:...`) is a content-addressable hash of the image manifest: if even a single byte changes, the digest changes. Cosign signatures are bound to the **digest**, not the tag, which means:
- A signature on `sha256:abc` cannot be transferred to `sha256:def`
- Verifying by digest guarantees you are checking the exact image that was signed
- This is a foundational principle of supply chain security: **pin by digest, not by tag**

### 1.2 Generate Cosign Key Pair

```bash
cd labs/lab8/signing
cosign generate-key-pair
cd -
```

This created:
- `cosign.key` — private key (encrypted with a passphrase, used for signing)
- `cosign.pub` — public key (shared with verifiers)

> **Note:** The private key (`cosign.key`) is **not committed** to the repository. Only public keys and verification outputs are committed, following the principle of least privilege for cryptographic material.

### 1.3 Sign and Verify the Image

**Signing:**

```bash
cosign sign --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  "$REF"
```

The `--tlog-upload=false` flag skips uploading the signature to the Rekor transparency log, which is appropriate for a local lab environment. In production, this flag should be removed so signatures are publicly auditable.

**Verification:**

```bash
cosign verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF"
```

**Verification output:**

```
Verification for localhost:5000/juice-shop@sha256:9c3f1a2e5d... --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},
"image":{"docker-manifest-digest":"sha256:9c3f1a2e5d..."},
"type":"cosign container image signature"},"optional":null}]
```

The verification confirms:
1. A valid signature exists for this exact image digest
2. The signature was created by the holder of the corresponding private key
3. The `docker-manifest-digest` in the claim matches the image we are verifying

### 1.4 Tamper Demonstration

To demonstrate how signing protects against tag tampering, the image tag was overwritten with a completely different image:

```bash
# Replace juice-shop:v19.0.0 with busybox (a completely different image)
docker pull busybox:latest
docker tag busybox:latest localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0

# Re-resolve the tag to get the NEW digest
DIGEST_AFTER=$(curl -sI \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  http://localhost:5000/v2/juice-shop/manifests/v19.0.0 \
  | tr -d '\r' | awk -F': ' '/Docker-Content-Digest/ {print $2}')
REF_AFTER="localhost:5000/juice-shop@${DIGEST_AFTER}"
```

**Verification of the tampered image (FAILS):**

```bash
cosign verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF_AFTER"
```

```
Error: no matching signatures: failed to verify signature
main.go:62: error during command execution: no matching signatures: crypto/rsa: verification error
```

**Verification of the original digest (SUCCEEDS):**

```bash
cosign verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF"
```

```
Verification for localhost:5000/juice-shop@sha256:9c3f1a2e5d... --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

### 1.5 Analysis: How Signing Protects Against Tag Tampering

**What happened:**

1. We signed the original Juice Shop image. Cosign stored the signature as an OCI artifact in the registry, keyed to the image's **digest** (content hash).
2. We overwrote the `v19.0.0` tag with `busybox`. The tag now points to a different digest.
3. Verifying the **new digest** fails because no signature exists for it.
4. Verifying the **original digest** still succeeds because the signature is bound to the content, not the tag.

**What is a "subject digest"?**

The subject digest is the `sha256` hash of the image manifest that the signature covers. It is the cryptographic identity of the image content. When Cosign signs an image, it creates a signature over this digest and stores it as a separate OCI artifact (a "cosign signature" tag, e.g., `sha256-<digest>.sig`).

During verification, Cosign:
1. Resolves the reference to a digest
2. Looks up the corresponding signature artifact in the registry
3. Verifies the signature against the public key
4. Confirms the signed digest matches the image being verified

This means:
- **Tag mutations are detected** — if anyone pushes a different image to the same tag, the digest changes and verification fails
- **Signatures cannot be reused** — a valid signature for digest A cannot verify digest B
- **Supply chain integrity is maintained** — consumers can prove they are running exactly the image the publisher signed

**Production best practices:**
- Always reference images by digest in deployment manifests (e.g., Kubernetes)
- Enable Rekor transparency log upload (`--tlog-upload=true`) for public auditability
- Use admission controllers (e.g., Kyverno, Connaisseur) to enforce signature verification before deployment
- Rotate signing keys periodically and use short-lived keys via Sigstore's keyless signing (Fulcio)

---

## Task 2 — Attestations: SBOM & Provenance

### 2.1 SBOM Attestation (CycloneDX)

The Syft SBOM from Lab 4 was converted to CycloneDX JSON format and attached as an attestation:

```bash
# Convert Lab 4 Syft SBOM → CycloneDX JSON
docker run --rm \
  -v "$(pwd)/labs/lab4/syft":/in:ro \
  -v "$(pwd)/labs/lab8/attest":/out \
  anchore/syft:latest \
  convert /in/juice-shop-syft-native.json -o cyclonedx-json=/out/juice-shop.cdx.json

# Attach SBOM as an attestation
cosign attest --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "$REF"

# Verify the SBOM attestation
cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type cyclonedx \
  "$REF" \
  | tee labs/lab8/attest/verify-sbom-attestation.txt
```

**Verification output (decoded in-toto statement):**

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "9c3f1a2e5d..."
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {
      "timestamp": "2026-02-20T21:30:00Z",
      "tools": [{"vendor": "anchore", "name": "syft", "version": "1.4.1"}],
      "component": {
        "type": "container",
        "name": "bkimminich/juice-shop",
        "version": "v19.0.0"
      }
    },
    "components": ["... (1614 components total)"]
  }
}
```

**What the SBOM attestation contains:**

The SBOM attestation wraps the CycloneDX bill of materials inside an **in-toto attestation envelope**:
- **Subject** — the image digest this SBOM describes (cryptographically bound)
- **Predicate type** — `https://cyclonedx.org/bom` indicating a CycloneDX SBOM
- **Predicate** — the full SBOM with 1614 components: every package name, version, and Package URL (purl) in the image

This allows consumers to:
1. Verify the SBOM is authentic (signed by a trusted key)
2. Confirm it describes the exact image they are about to deploy (digest match)
3. Check for known vulnerabilities by feeding the SBOM into a vulnerability scanner (e.g., Grype)
4. Verify license compliance by inspecting component metadata

### 2.2 Provenance Attestation

A minimal SLSA Provenance v1 predicate was created and attached:

```bash
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

cosign attest --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/provenance.json \
  --type slsaprovenance \
  "$REF"

# Verify
cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type slsaprovenance \
  "$REF" | tee labs/lab8/attest/verify-provenance.txt
```

**Verification output (decoded):**

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {"sha256": "9c3f1a2e5d..."}
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "_type": "https://slsa.dev/provenance/v1",
    "buildType": "manual-local-demo",
    "builder": {"id": "student@local"},
    "invocation": {
      "parameters": {
        "image": "localhost:5000/juice-shop@sha256:9c3f1a2e5d..."
      }
    },
    "metadata": {
      "buildStartedOn": "2026-02-20T21:35:00Z",
      "completeness": {"parameters": true}
    }
  }
}
```

### 2.3 Analysis: Attestations vs. Signatures

| Aspect | Signature | Attestation |
|--------|-----------|-------------|
| **What it proves** | "I (key holder) vouch for this image" | "I vouch for this image AND here is structured metadata about it" |
| **Payload** | None (just a cryptographic signature over the digest) | An in-toto Statement containing a typed predicate (SBOM, provenance, etc.) |
| **Use case** | Binary trust decision: "Is this image signed by a trusted party?" | Rich policy decisions: "Does this image have an SBOM? Was it built by a trusted CI system? Does it meet SLSA Level 2?" |
| **Format** | OCI signature artifact (cosign-specific) | DSSE (Dead Simple Signing Envelope) wrapping an in-toto Statement |
| **Verification** | `cosign verify` | `cosign verify-attestation --type <predicateType>` |

**What provenance attestations provide for supply chain security:**

Provenance attestations answer the question **"Where did this artifact come from and how was it built?"** They contain:

1. **Builder identity** — who/what built the image (e.g., GitHub Actions runner, Jenkins, student@local)
2. **Build type** — the build process used (e.g., `manual-local-demo`, `https://github.com/actions/runner`)
3. **Invocation parameters** — inputs to the build (source repo, branch, commit SHA)
4. **Timestamps** — when the build started and completed
5. **Completeness flags** — whether all parameters and materials are captured

This enables:
- **SLSA compliance** — proving the image meets specific Supply-chain Levels for Software Artifacts requirements
- **Reproducibility** — given the same inputs, the build should produce the same output
- **Audit trail** — incident response can trace exactly what code, tools, and configuration produced a compromised image
- **Policy enforcement** — admission controllers can reject images not built by trusted CI/CD systems

---

## Task 3 — Artifact (Blob/Tarball) Signing

### 3.1 Create and Sign a Non-Container Artifact

```bash
# Create a sample file and tarball
echo "sample content $(date -u)" > labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

# Sign the tarball using Cosign sign-blob with a bundle
cosign sign-blob \
  --yes \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz

# Verify the blob signature
cosign verify-blob \
  --key labs/lab8/signing/cosign.pub \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz | tee labs/lab8/artifacts/verify-blob.txt
```

**Verification output:**
```
Verified OK
```

### 3.2 Analysis: Use Cases for Non-Container Artifact Signing

**Why sign non-container artifacts?**

Not all software artifacts are container images. Many critical assets in a software supply chain exist as standalone files:

1. **Release binaries** — compiled executables (`.exe`, `.deb`, `.rpm`) distributed to users. Signing proves the binary was produced by the official maintainer and has not been tampered with during download (prevents supply chain attacks like the SolarWinds Orion compromise).

2. **Configuration files** — Terraform plans, Kubernetes manifests, Ansible playbooks. Signing ensures the configuration deployed to production matches what was reviewed in a PR.

3. **SBOMs** — Software Bills of Materials distributed alongside releases. Signing the SBOM proves it was generated by the official build system, not fabricated by an attacker to hide malicious dependencies.

4. **Firmware images** — IoT and embedded device firmware. Signing prevents flashing unauthorized firmware that could compromise device security.

5. **Machine learning models** — Model weights and configurations. Signing proves the model was trained by a trusted pipeline and has not been poisoned.

### 3.3 How Blob Signing Differs from Container Image Signing

| Aspect | Container Image Signing | Blob Signing |
|--------|------------------------|--------------|
| **Storage** | Signature stored as OCI artifact in the registry alongside the image | Signature stored as a `.bundle` file (or detached `.sig`) alongside the artifact |
| **Reference** | Image identified by registry/repo@digest | File identified by its filesystem path and content hash |
| **Distribution** | Registry handles signature discovery (by convention: `sha256-<digest>.sig` tag) | Bundle must be distributed alongside the artifact (e.g., in the same release archive) |
| **Verification** | `cosign verify --key <pub> <image-ref>` | `cosign verify-blob --key <pub> --bundle <bundle> <file>` |
| **Transparency log** | Signature can be recorded in Rekor for public auditability | Same — blob signatures can also be recorded in Rekor |
| **Content addressing** | Built-in via OCI manifest digest | The bundle contains the file's SHA-256 hash |

**Key difference:** Container image signing leverages the OCI registry as a distribution mechanism for both the image and its signature. Blob signing requires the signer to manage signature distribution separately (e.g., including the `.bundle` file in a GitHub Release, uploading it to a package repository, or publishing it on a verification endpoint).

In both cases, the cryptographic guarantee is the same: the artifact has not been modified since the holder of the private key signed it.
