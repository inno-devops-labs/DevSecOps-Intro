# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Target Image

- `bkimminich/juice-shop:v19.0.0`
- Local registry image reference:
  - original digest: see `labs/lab8/analysis/ref.txt`
  - tampered digest: see `labs/lab8/analysis/ref-after-tamper.txt`

---

## Task 1 — Local Registry, Signing & Verification

### Local Registry Setup

A local registry was started on `localhost:5000`, and the target image was pushed there.

The image was referenced by **digest** rather than by tag. This is important because tags are mutable, while digests are immutable cryptographic identifiers of the exact image content.

### Cosign Key Pair

A local Cosign key pair was generated:

- public key: `labs/lab8/signing/cosign.pub`
- private key: `labs/lab8/signing/cosign.key`

The private key was excluded from version control.

### Image Signing and Verification

The original Juice Shop image in the local registry was signed with Cosign and then successfully verified with the public key.

Evidence:
- signing log: `labs/lab8/signing/sign-image.txt`
- verification log: `labs/lab8/signing/verify-image.txt`

### What “subject digest” means

The subject digest is the immutable hash of the signed artifact.  
It identifies the exact image contents, not just the tag.

This matters because a tag such as `v19.0.0` can later be moved to another image, but the digest always points to one exact manifest.

### Tamper Demonstration

A tamper scenario was demonstrated by overwriting the tag `localhost:5000/juice-shop:v19.0.0` with `busybox:latest`.

Results:
- verification of the **new digest** failed (`no signatures found`)
- verification of the **original digest** still succeeded

This proves that signing protects against tag tampering when verification is performed by digest.

Evidence:
- tampered digest reference: `labs/lab8/analysis/ref-after-tamper.txt`
- failed verification of tampered image: `labs/lab8/signing/verify-after-tamper.txt`
- successful verification of original signed digest: `labs/lab8/signing/verify-original-after-tamper.txt`

---

## Task 2 — Attestations: SBOM and Provenance

### How attestations differ from signatures

A **signature** proves authenticity and integrity of the artifact itself.

An **attestation** is a signed statement about the artifact.  
It does not just say “this image is signed”, but also provides signed metadata describing the image.

### SBOM Attestation

A CycloneDX SBOM was created from Syft output and attached as an attestation.

Files:
- SBOM predicate: `labs/lab8/attest/juice-shop.cdx.json`
- SBOM attestation log: `labs/lab8/attest/attest-sbom.txt`
- verification log: `labs/lab8/attest/verify-sbom-attestation.txt`
- formatted payload: `labs/lab8/attest/verify-sbom-attestation.pretty.json`

The SBOM attestation contains software inventory information such as:
- package names
- package versions
- dependency/component metadata

This improves software supply chain transparency because consumers can inspect exactly what is inside the image.

### Provenance Attestation

A minimal provenance predicate was created and attached using the `slsaprovenance` type.

Files:
- predicate file: `labs/lab8/attest/provenance.json`
- provenance attestation log: `labs/lab8/attest/attest-provenance.txt`
- verification log: `labs/lab8/attest/verify-provenance.txt`
- formatted payload: `labs/lab8/attest/verify-provenance.pretty.json`

The provenance attestation provides metadata about:
- builder identity
- build type
- invocation parameters
- build timestamp

This is useful for supply chain security because it adds traceability and helps verify how the artifact was produced.

### Payload Inspection

Both SBOM and provenance verification outputs were inspected and reformatted with `jq` for readability.

---

## Task 3 — Artifact (Blob/Tarball) Signing

A non-container artifact was created and signed:

- source file: `labs/lab8/artifacts/sample.txt`
- tarball: `labs/lab8/artifacts/sample.tar.gz`
- bundle: `labs/lab8/artifacts/sample.tar.gz.bundle`

Evidence:
- signing log: `labs/lab8/artifacts/sign-blob.txt`
- verification log: `labs/lab8/artifacts/verify-blob.txt`

### Use Cases for Signing Non-Container Artifacts

Blob signing is useful for:
- release binaries
- tarballs
- configuration bundles
- scripts
- policy files
- deployment assets

### How Blob Signing Differs from Image Signing

Container image signing works with OCI images stored in a registry.

Blob signing works directly with local files on disk.

Both provide authenticity and integrity, but image signing is registry-oriented while blob signing is file-oriented.

---

## Conclusion

This lab demonstrated key software supply chain security controls:

- signing a container image with Cosign
- verifying a signed digest
- detecting tampering through digest-based verification
- attaching and verifying SBOM attestations
- attaching and verifying provenance attestations
- signing and verifying a non-container artifact

The main lesson is that trust should be anchored to **immutable digests and signed metadata**, not to mutable tags alone.
