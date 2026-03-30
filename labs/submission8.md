# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Environment

- Date: 2026-03-30
- OS: macOS (Darwin 25.3.0, arm64)
- Branch: `feature/lab8`
- Docker: 29.2.0
- Cosign: v3.0.5
- Target image: `bkimminich/juice-shop:v19.0.0`
- Local registry: `localhost:5050` (registry:3, port 5050 due to macOS AirPlay on 5000)

---

## Task 1 — Local Registry, Signing & Verification (4 pts)

### 1.1 Image Push to Local Registry

The image was pulled and pushed to a local Distribution v3 registry:

```
docker pull bkimminich/juice-shop:v19.0.0
docker run -d --restart=always -p 5050:5000 --name registry registry:3
docker tag bkimminich/juice-shop:v19.0.0 localhost:5050/juice-shop:v19.0.0
docker push localhost:5050/juice-shop:v19.0.0
```

Digest reference resolved via OCI manifest (the image uses OCI format, not Docker v2):

```
DIGEST=sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5
REF=localhost:5050/juice-shop@sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5
```

### 1.2 Key Pair Generation

A Cosign key pair was generated in `labs/lab8/signing/`:

```
cosign generate-key-pair
# -> cosign.key (private, NOT committed) and cosign.pub (public)
```

### 1.3 Signing and Verification

**Signing** (using Cosign v3 signing-config instead of deprecated `--tlog-upload=false`):

```
cosign sign --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/signing-config.json \
  --key labs/lab8/signing/cosign.key \
  "$REF"
```

Output: `Signing artifact...` — signature pushed to the local registry as an OCI artifact alongside the image.

**Verification:**

```
cosign verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF"
```

Output:

```
Verification for localhost:5050/juice-shop@sha256:772d623...dcbff3a5 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5050/juice-shop@sha256:772d623..."},...}}]
```

### 1.4 Tamper Demonstration

**Tamper:** Pushed `busybox:latest` under the same tag `juice-shop:v19.0.0`:

```
docker pull busybox:latest
docker tag busybox:latest localhost:5050/juice-shop:v19.0.0
docker push localhost:5050/juice-shop:v19.0.0
```

New digest after tamper: `sha256:c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6`

**Verification of tampered digest — FAILED as expected:**

```
cosign verify --allow-insecure-registry --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "localhost:5050/juice-shop@sha256:c4e5b27b..."

Error: no signatures found
```

**Verification of original digest — still PASSED:**

```
cosign verify --allow-insecure-registry --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "localhost:5050/juice-shop@sha256:772d6234..."

Verification for localhost:5050/juice-shop@sha256:772d623... --
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

### 1.5 Analysis: Signing and Tag Tampering

**How signing protects against tag tampering:**

Tags are mutable pointers — anyone with push access can reassign a tag to a different image (as demonstrated by pushing `busybox` under `juice-shop:v19.0.0`). Cosign signatures are bound to the image's content-addressable **digest**, not the tag. When an attacker replaces the image behind a tag, the new image has a different digest, and the signature does not apply to it. Verification fails because:

1. The signature references the original digest in its `docker-manifest-digest` claim
2. The new image at the tag has a different digest with no corresponding signature
3. Cosign refuses to verify — there are literally "no signatures found" for the tampered digest

**What "subject digest" means:**

The "subject digest" is the SHA-256 hash of the image manifest. It is a content-addressable identifier: any change to the image layers, configuration, or metadata produces a completely different digest. Unlike tags (which are human-readable aliases that can be reassigned), digests are immutable and cryptographically tied to the exact image content. This is why all signing and verification should use digest references (`image@sha256:...`) rather than tag references (`image:tag`).

---

## Task 2 — Attestations: SBOM & Provenance (4 pts)

### 2.1 SBOM Attestation (CycloneDX)

The Syft-native SBOM from Lab 4 was converted to CycloneDX JSON:

```
docker run --rm \
  -v "$(pwd)/labs/lab4/syft":/in:ro \
  -v "$(pwd)/labs/lab8/attest":/out \
  anchore/syft:latest \
  convert /in/juice-shop-syft-native.json -o cyclonedx-json=/out/juice-shop.cdx.json
```

SBOM attestation attached and verified:

```
cosign attest --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/signing-config.json \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "$REF"

cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type cyclonedx \
  "$REF"
```

**Decoded SBOM attestation payload (summary):**

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "localhost:5050/juice-shop",
      "digest": {
        "sha256": "772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5"
      }
    }
  ],
  "predicate_bomFormat": "CycloneDX",
  "predicate_specVersion": "1.6",
  "predicate_components_count": 3532
}
```

The attestation wraps the CycloneDX SBOM inside an in-toto Statement envelope. The `subject` field binds the SBOM to the exact image digest, and the `predicate` contains the full CycloneDX BOM with 3532 components.

### 2.2 Provenance Attestation

A minimal SLSA Provenance v1 predicate was created and attached:

```json
{
  "_type": "https://slsa.dev/provenance/v1",
  "buildType": "manual-local-demo",
  "builder": {"id": "student@local"},
  "invocation": {"parameters": {"image": "localhost:5050/juice-shop@sha256:772d623..."}},
  "metadata": {"buildStartedOn": "2026-03-30T10:30:18Z", "completeness": {"parameters": true}}
}
```

Verified provenance attestation — decoded payload:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "localhost:5050/juice-shop",
      "digest": { "sha256": "772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5" }
    }
  ],
  "predicate": {
    "builder": { "id": "student@local" },
    "buildType": "manual-local-demo",
    "invocation": {
      "parameters": { "image": "localhost:5050/juice-shop@sha256:772d623..." }
    },
    "metadata": {
      "buildStartedOn": "2026-03-30T10:30:18Z",
      "completeness": { "parameters": true, "environment": false, "materials": false },
      "reproducible": false
    }
  }
}
```

### 2.3 Analysis: Attestations vs. Signatures

**How attestations differ from signatures:**

| Aspect | Signature | Attestation |
|--------|-----------|-------------|
| **What it proves** | The image was signed by a specific key holder | Structured claims *about* the image, signed by a key holder |
| **Content** | A cryptographic signature over the image digest | An in-toto Statement envelope containing a typed predicate (SBOM, provenance, etc.) |
| **Granularity** | Binary yes/no — "this image is approved" | Rich metadata — *what* components are inside, *how* it was built, *when*, *by whom* |
| **Use case** | Gate deployment: "only deploy signed images" | Policy enforcement: "only deploy images with SBOM showing no critical CVEs" or "only deploy images built by CI/CD" |

**What the SBOM attestation contains:**

The CycloneDX SBOM attestation contains a complete inventory of 3532 software components in the image, including package names, versions, licenses, and dependency relationships. This allows downstream consumers to:
- Check for known vulnerabilities without re-scanning the image
- Verify license compliance
- Audit the software supply chain for unexpected or unauthorized dependencies

**What provenance attestations provide:**

Provenance attestations answer "who built this, when, how, and from what source?" They provide:
- **Builder identity** — which system or person produced the artifact
- **Build timestamp** — when the build occurred
- **Build parameters** — what configuration/inputs were used
- **Completeness indicators** — whether the provenance captures all relevant materials and environment details

In supply chain security, provenance enables policies like "only deploy images built by our CI/CD system from the main branch" — preventing deployment of images built on developer laptops or by compromised third parties.

---

## Task 3 — Artifact (Blob/Tarball) Signing (2 pts)

### 3.1 Blob Signing and Verification

A sample tarball was created and signed:

```
echo "sample content $(date -u)" > labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

cosign sign-blob --yes \
  --signing-config labs/lab8/signing/signing-config.json \
  --key labs/lab8/signing/cosign.key \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz
```

Output:

```
Using payload from: labs/lab8/artifacts/sample.tar.gz
Signing artifact...
Wrote bundle to file labs/lab8/artifacts/sample.tar.gz.bundle
```

**Verification:**

```
cosign verify-blob \
  --key labs/lab8/signing/cosign.pub \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  --insecure-ignore-tlog \
  labs/lab8/artifacts/sample.tar.gz
```

Output:

```
Verified OK
```

### 3.2 Analysis: Non-Container Artifact Signing

**Use cases for signing non-container artifacts:**

1. **Release binaries** — signing CLI tools, libraries, or compiled binaries ensures users can verify they downloaded the authentic artifact from the publisher, not a tampered copy from a compromised mirror or CDN
2. **Configuration files** — signing Terraform plans, Kubernetes manifests, or Ansible playbooks ensures that infrastructure-as-code has not been modified between review/approval and deployment
3. **SBOMs and scan reports** — signing security artifacts guarantees their integrity; an attacker cannot modify an SBOM to hide a vulnerability
4. **Firmware updates** — embedded and IoT devices verify firmware signatures before flashing to prevent malicious firmware injection

**How blob signing differs from container image signing:**

| Aspect | Container Image Signing | Blob Signing |
|--------|------------------------|-------------|
| **Storage** | Signature stored in the OCI registry alongside the image (as a tag/referrer) | Signature stored as a separate `.bundle` file alongside the artifact |
| **Reference** | Bound to the image digest within the registry | Bound to the file content hash |
| **Distribution** | Signature travels with the image through registry pull/push | Bundle file must be distributed separately alongside the artifact |
| **Verification** | Requires registry access to fetch the signature | Only requires the bundle file and public key — fully offline |
| **Ecosystem** | Integrated with container runtimes and admission controllers (e.g., Kyverno, Sigstore Policy Controller) | Requires manual or scripted verification in CI/CD pipelines |

---

## Appendix: Artifacts and Evidence

### File Structure

```
labs/lab8/
├── .gitignore              # Excludes private keys from version control
├── analysis/
│   ├── ref.txt                         # Original digest reference
│   ├── ref-after-tamper.txt            # Tampered digest reference
│   ├── sign-output.txt                 # Cosign sign output
│   ├── verify-output.txt              # Successful verification
│   ├── verify-tampered.txt            # Failed verification (tampered)
│   └── verify-original-after-tamper.txt # Original still verifies
├── signing/
│   ├── cosign.pub                     # Public key (committed)
│   └── signing-config.json            # Cosign v3 signing config (no Rekor)
├── attest/
│   ├── juice-shop.cdx.json           # CycloneDX SBOM
│   ├── provenance.json               # SLSA provenance predicate
│   ├── attest-sbom-output.txt        # SBOM attestation output
│   ├── attest-provenance-output.txt  # Provenance attestation output
│   ├── verify-sbom-attestation.txt   # SBOM attestation verification
│   ├── verify-provenance.txt         # Provenance attestation verification
│   ├── sbom-payload-summary.json     # Decoded SBOM attestation summary
│   └── provenance-payload-decoded.json # Decoded provenance payload
└── artifacts/
    ├── sample.txt                     # Source file
    ├── sample.tar.gz                  # Signed tarball
    ├── sample.tar.gz.bundle           # Cosign bundle (signature + metadata)
    ├── sign-blob-output.txt           # Blob signing output
    └── verify-blob.txt                # Blob verification output
```

### Cosign v3 Note

Cosign v3.0.5 deprecated the `--tlog-upload=false` flag in favor of a `--signing-config` file that omits Rekor transparency log URLs. The signing config was generated from the Sigstore public instance config with `rekorTlogUrls` removed:

```bash
curl -s https://raw.githubusercontent.com/sigstore/root-signing/.../signing_config.v0.2.json \
  | jq 'del(.rekorTlogUrls)' > signing-config.json
```

This achieves the same result as the deprecated flag — signing locally without uploading to Rekor — while following the new Cosign v3 configuration model.

### Key Digests

| Reference | Digest |
|-----------|--------|
| Original image | `sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5` |
| Tampered image (busybox) | `sha256:c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6` |
