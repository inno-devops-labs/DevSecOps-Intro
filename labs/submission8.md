# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Local Registry, Signing & Verification

### Tag Tampering and Protection via Signing

In this lab, container image signing was performed using Cosign with a locally hosted registry. The key security concept demonstrated is that **Docker tags are mutable**, while **image digests are immutable**.

A tampering scenario was executed by replacing the original `juice-shop:v19.0.0` image with a different image (`busybox`) under the same tag. Although the tag remained unchanged, the underlying image content—and therefore its digest—changed.

Cosign signatures are bound to the **image digest**, not the tag. As a result:

* Verification of the **new (tampered) digest failed**, because it was not signed with the original key
* Verification of the **original digest succeeded**, confirming the integrity of the originally signed image

This demonstrates that signing protects against tag tampering by ensuring that only the exact, signed image (identified by its digest) can be verified successfully.

### Subject Digest Explanation

The **subject digest** refers to the cryptographic hash (e.g., SHA256) of the container image manifest. It uniquely identifies the exact image content.

Unlike tags, which can be reassigned, the digest is:

* Immutable
* Content-addressable
* Used as the reference for signing and verification

Therefore, Cosign uses the subject digest to ensure that signatures are tied to a specific, unchangeable image.

---

## Task 2 — Attestations: SBOM and Provenance

### Difference Between Signatures and Attestations

A **signature** proves the authenticity and integrity of an artifact by confirming who signed it and that it has not been modified.

An **attestation**, on the other hand, is a signed piece of metadata attached to an artifact. It provides additional context about the artifact, such as:

* What it contains (SBOM)
* How it was built (provenance)

In summary:

* Signature — "Who signed it?"
* Attestation — "What is it / how was it created?"

---

### SBOM Attestation

An SBOM (Software Bill of Materials) attestation was generated and attached to the container image using the CycloneDX format.

The SBOM contains:

* A list of software components included in the image
* Dependency relationships
* Versions of libraries and packages

This information is critical for:

* Identifying known vulnerabilities
* Performing dependency analysis
* Improving transparency in the software supply chain

---

### Provenance Attestation

A provenance attestation provides metadata about how the artifact was built.

In this lab, a minimal SLSA provenance predicate was created, containing:

* Builder identity
* Build parameters (image reference)
* Timestamp of the build process

Provenance attestations improve supply chain security by:

* Enabling traceability of the build process
* Verifying the origin of artifacts
* Supporting trust in automated pipelines

---

## Task 3 — Artifact (Blob/Tarball) Signing

### Use Cases for Signing Non-Container Artifacts

Blob signing was used to sign a `.tar.gz` archive, demonstrating how Cosign can be applied beyond container images.

Common use cases include:

* Signing release binaries
* Protecting configuration files
* Verifying distributed archives
* Securing software artifacts outside of container registries

---

### Difference Between Blob Signing and Container Image Signing

Blob signing differs from container image signing in several key ways:

| Aspect       | Container Signing     | Blob Signing             |
| ------------ | --------------------- | ------------------------ |
| Storage      | Container registry    | Local file system        |
| Reference    | Image digest          | File path                |
| Metadata     | Supports attestations | No built-in attestations |
| Distribution | OCI registry-based    | Standalone files         |

Blob signing operates directly on files and produces a signature bundle that can be used for offline verification.

