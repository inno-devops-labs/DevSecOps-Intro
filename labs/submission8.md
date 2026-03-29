# Software Supply Chain Security: Signing, Verification & Attestations

## Image Signing & Verification

### Local Registry Signing Results

The OWASP Juice Shop image `bkimminich/juice-shop:v19.0.0` was pushed to a local registry (`localhost:5000`), signed with Cosign, and verified using the corresponding public key. Because Cosign v3 deprecates this workflow and prefers an explicit signing configuration without Rekor, a local `signing-config.json` was used.

| Item | Result |
|------|--------|
| Source image | `bkimminich/juice-shop:v19.0.0` |
| Signed local subject digest | `localhost:5000/juice-shop@sha256:547bd3f...` |
| Verification before tampering | Success |
| Verification after tag tampering | Failed |
| Verification of original digest after tampering | Success |

Evidence: `labs/lab8/signing/sign-output.txt`, `verify-success.txt`, `verify-tampered.txt`, `labs/lab8/analysis/ref.txt`.

### Tamper Demonstration & Analysis

**How signing protects against tag tampering:**  
A tag (e.g., `v19.0.0`) is mutable – it can be repointed to any manifest. A signature is bound to the **subject digest** (cryptographic hash of the exact manifest). If an attacker changes the tag to a different image, the digest changes, and the original signature no longer matches → verification fails. The original digest remains verifiable.

**Subject digest** means the unique content address of the image manifest. Signing by digest ensures that the signature cannot be reused for any other content.

| Check | Reference | Result |
|-------|-----------|--------|
| Original signed digest | `sha256:547bd3f...` | Verified |
| Tampered digest (busybox) | `sha256:b8d1827...` | Failed (exit code 10) |


## Attestations: SBOM & Provenance

### Attestation Summary

Two attestations were attached to the signed image digest and verified with the same public key.

| Attestation Type | Predicate Type | Key Information | Verification Result |
|------------------|----------------|-----------------|---------------------|
| SBOM (CycloneDX) | `https://cyclonedx.org/bom` | Component `bkimminich/juice-shop:v19.0.0`, **3533 components** | Success |
| Provenance (SLSA v0.2) | `https://slsa.dev/provenance/v0.2` | `buildType=manual-local-demo`, builder `student@local`, timestamp `2026-03-29T12:26:24Z` | Success |

Evidence: `labs/lab8/attest/juice-shop.cdx.json`, `provenance.json`, `verify-sbom-attestation.txt`, `verify-provenance.txt`.

### Signatures vs. Attestations

| Concept | Purpose | Example |
|---------|---------|---------|
| **Signature** | Proves artifact digest was signed by a specific key (integrity + authenticity) | `cosign verify` confirms the image hasn’t been tampered with |
| **Attestation** | Proves structured claims (metadata) about that digest were signed | SBOM lists all packages; provenance records build info |

Both are needed for mature supply chain security: signatures protect integrity, attestations add context and traceability.

### SBOM Attestation Value

- Provides a **verifiable package inventory** (npm, Debian packages, binaries).
- Enables **vulnerability correlation** when new CVEs are published.
- Supports **license compliance** and incident response.

### Provenance Attestation Value

- Answers **who, when, and how** the artifact was built.
- In a real CI/CD pipeline, provenance would include source repository, build command, and builder identity.
- Helps **detect supply chain substitution** attacks (e.g., an attacker replacing a legitimate image with a malicious one that claims the same provenance).


## Non-Container Artifact (Blob) Signing

### Blob Signing Results

A text file was archived into `sample.tar.gz`, signed with `cosign sign-blob`, and verified with `cosign verify-blob`.

| Item | Result |
|------|--------|
| Artifact | `labs/lab8/artifacts/sample.tar.gz` |
| SHA-256 | `91552cfd...` |
| Signature format | Sigstore bundle |
| Verification result | `Verified OK` |

Evidence: `labs/lab8/artifacts/sign-blob.txt`, `verify-blob.txt`.

### Use Cases and Comparison with Image Signing

**Use cases for blob signing:**
- Release archives (`.tar.gz`, `.zip`)
- Standalone binaries (CLI tools)
- Configuration files, policy bundles
- SBOM or provenance files themselves

**Differences from container image signing:**

| Aspect | Image Signing | Blob Signing |
|--------|--------------|--------------|
| Storage | OCI registry (separate manifest) | Standalone signature file or bundle |
| Distribution | Together with image (registry) | Must be distributed alongside blob |
| Integration | Tight with registry workflows | General‑purpose, any file |
| Verification | `cosign verify` | `cosign verify-blob` |

Both provide integrity and signer authenticity, but blob signing is more flexible for non‑container artifacts.
