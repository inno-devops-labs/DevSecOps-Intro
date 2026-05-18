# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Image Signing & Verification

- Pushed `bkimminich/juice-shop:v19.0.0` to a local registry (`localhost:5002`)
- Used digest-based reference instead of tag to ensure immutability
- Generated a Cosign key pair and signed the container image using `cosign sign`

### Verification
- Verified signature successfully using public key
- Verification confirmed:
  - Valid cosign claims
  - Signature matches the image digest
  - Integrity of the container image is guaranteed

### Tamper demonstration
- Image tag was reassigned to a different image (busybox scenario)
- New digest did not match the original signed digest
- Verification failed for the modified image
- Original signed digest still verifies successfully

### Conclusion
Image signing binds the signature to a specific immutable digest. Any modification of the image results in a new digest, breaking signature validation and preventing tampering.

---

## Task 2 — Attestations (SBOM & Provenance)

### SBOM Attestation
- Generated CycloneDX SBOM from Syft output
- Attached SBOM as a Cosign attestation using `cosign attest`
- Verified attestation using `cosign verify-attestation`

#### SBOM content includes:
- Full dependency list of the container image
- Package metadata and versions
- Software composition structure

### Provenance Attestation
- Created a minimal SLSA v1 provenance predicate
- Attached provenance using Cosign attestation mechanism
- Verified successfully using `cosign verify-attestation`

#### Provenance provides:
- Build timestamp
- Build environment metadata
- Traceability of artifact origin
- Supply chain transparency

### Difference between signature and attestation
- Signature: ensures integrity and authenticity of the image
- Attestation: provides additional metadata about the artifact (SBOM, provenance)

---

## Task 3 — Artifact (Blob) Signing

- Created a tar.gz archive as a sample artifact
- Signed the artifact using `cosign sign-blob` with bundle format
- Verified signature using `cosign verify-blob`

### Use cases for blob signing:
- Release binaries
- Configuration files
- Backup archives
- Non-container artifacts in CI/CD pipelines

### Difference from image signing:
- Image signing applies to container registry artifacts using digests
- Blob signing applies to arbitrary files using standalone signatures (bundle-based verification)

---

## Conclusion

This lab demonstrated end-to-end software supply chain security using Cosign:

- Container image integrity was ensured using digest-based signing
- Attestations (SBOM and provenance) added transparency and traceability
- Non-container artifacts were secured using blob signing

Overall, Cosign provides a unified mechanism for signing, verifying, and attaching metadata to software artifacts, improving trust in the software supply chain.