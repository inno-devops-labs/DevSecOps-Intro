# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

**Target image:** `bkimminich/juice-shop:v19.0.0`
**Tool:** Cosign v3.0.5

---

## Task 1 — Local Registry, Signing & Verification

### 1.1 Local Registry Setup

Image pushed to local registry (`registry:3` on `localhost:5000`):

```
docker run -d --restart=always -p 5000:5000 --name registry registry:3
docker tag bkimminich/juice-shop:v19.0.0 localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

Digest reference (OCI manifest):
```
localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58
```

### 1.2 Key Pair Generation

```
cosign generate-key-pair --output-key-prefix labs/lab8/signing/cosign
```
- Private key: `labs/lab8/signing/cosign.key`
- Public key: `labs/lab8/signing/cosign.pub`

### 1.3 Signing & Verification

> **Note:** Cosign v3 deprecated `--tlog-upload=false`. A signing config without transparency log was used instead (`signing-config.json`).

**Sign:**
```
cosign sign --yes --allow-insecure-registry --allow-http-registry \
  --signing-config labs/lab8/signing/signing-config.json \
  --key labs/lab8/signing/cosign.key \
  "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
```

**Verify:**
```
cosign verify --allow-insecure-registry --allow-http-registry --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
```

**Result:** Verification succeeded
```
Verification for localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

### 1.4 Tamper Demonstration

Replaced `juice-shop:v19.0.0` tag with `busybox:latest`:
```
docker tag busybox:latest localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

New (tampered) digest: `sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65`

**Verify tampered image:** FAILED
```
Error: no signatures found
```

**Verify original digest:** PASSED — the original digest `sha256:547bd3...` still verifies successfully.

### Analysis: How Signing Protects Against Tag Tampering

Tags are mutable pointers — anyone with push access can overwrite a tag to point to a different image. Signing binds a cryptographic signature to a specific **content-addressable digest** (the SHA-256 hash of the image manifest), not the tag.

**"Subject digest"** is the immutable content hash of the image manifest that the signature covers. When you verify, Cosign checks:
1. The signature was produced by the expected key
2. The signature covers **exactly** this digest

If an attacker replaces the image behind a tag, the new image has a different digest and no valid signature. Verification fails with "no signatures found." The original digest remains verifiable because the signature is attached to the digest in the registry, not to the tag.

---

## Task 2 — Attestations: SBOM & Provenance

### 2.1 SBOM Attestation (CycloneDX)

SBOM generated from Lab 4 Syft output, converted to CycloneDX:
```
docker run --rm -v "%cd%\labs\lab4\syft:/in:ro" -v "%cd%\labs\lab8\attest:/out" \
  anchore/syft:latest convert /in/juice-shop-syft-native.json -o cyclonedx-json=/out/juice-shop.cdx.json
```

Attested and verified:
```
cosign attest --yes --allow-insecure-registry --allow-http-registry \
  --signing-config labs/lab8/signing/signing-config.json \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json --type cyclonedx \
  "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"

cosign verify-attestation --allow-insecure-registry --allow-http-registry --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub --type cyclonedx \
  "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
```

**Result:** SBOM attestation verified.

### 2.2 Provenance Attestation (SLSA)

Minimal SLSA Provenance v1 predicate created (`labs/lab8/attest/provenance.json`):
```json
{
  "_type": "https://slsa.dev/provenance/v1",
  "buildType": "manual-local-demo",
  "builder": {"id": "student@local"},
  "invocation": {"parameters": {"image": "localhost:5000/juice-shop@sha256:547bd3..."}},
  "metadata": {"buildStartedOn": "2026-03-30T19:05:00Z", "completeness": {"parameters": true}}
}
```

Attested and verified:
```
cosign verify-attestation --allow-insecure-registry --allow-http-registry --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub --type slsaprovenance \
  "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
```

**Result:** Provenance attestation verified. Decoded payload confirms the SLSA predicate with builder ID, build timestamp, and image reference.

### Analysis: Attestations vs Signatures

| Aspect | Signature | Attestation |
|--------|-----------|-------------|
| **What it proves** | The image was signed by a known key | Structured metadata **about** the image is signed |
| **Content** | Only identity + digest binding | Rich predicate (SBOM, provenance, scan results) |
| **Use case** | "I trust the publisher" | "I know what's inside and how it was built" |

**SBOM attestation** contains the full software bill of materials (CycloneDX format): every package name, version, license, and dependency relationship inside the image. This allows consumers to audit the image for known vulnerabilities or license compliance before deployment.

**Provenance attestation** provides build metadata: who built the image, when, with what parameters, and from what source. This enables supply chain traceability — verifying that an image came from a trusted CI/CD pipeline rather than a compromised developer machine.

---

## Task 3 — Artifact (Blob/Tarball) Signing

Created a sample tarball and signed it:
```
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

cosign sign-blob --yes \
  --signing-config labs/lab8/signing/signing-config.json \
  --key labs/lab8/signing/cosign.key \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz

cosign verify-blob \
  --key labs/lab8/signing/cosign.pub \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  --insecure-ignore-tlog \
  labs/lab8/artifacts/sample.tar.gz
```

**Result:** `Verified OK`

### Analysis: Blob Signing vs Container Image Signing

**Use cases for signing non-container artifacts:**
- Release binaries and installers — users verify downloads haven't been tampered with
- Configuration files and IaC templates — ensure deployment configs come from trusted sources
- SBOM/SARIF reports — prove security scan results are authentic
- Helm charts, Terraform modules — verify infrastructure-as-code integrity

**Key differences:**

| Aspect | Container Image Signing | Blob Signing |
|--------|------------------------|--------------|
| **Storage** | Signature stored in OCI registry alongside image | Signature stored in a `.bundle` file or separate `.sig` |
| **Reference** | Uses digest from registry manifest | Uses file hash computed locally |
| **Distribution** | Registry handles signature discovery | Bundle must be distributed alongside the artifact |
| **Verification** | `cosign verify` queries registry | `cosign verify-blob` uses local file + bundle |

---

## Files Produced

```
labs/lab8/
├── analysis/
│   ├── ref.txt
│   ├── ref-after-tamper.txt
│   ├── tamper-verify-fail.txt
│   └── tamper-verify-pass.txt
├── artifacts/
│   ├── sample.txt
│   ├── sample.tar.gz
│   ├── sample.tar.gz.bundle
│   └── verify-blob.txt
├── attest/
│   ├── juice-shop.cdx.json
│   ├── provenance.json
│   └── verify-provenance.txt
└── signing/
    ├── cosign.key
    ├── cosign.pub
    ├── signing-config.json
    └── verify-output.txt
```
