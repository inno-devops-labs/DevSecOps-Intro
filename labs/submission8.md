# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Local Registry, Signing & Verification

### Signing and Tag Tampering Protection

In this lab, I pushed the image `bkimminich/juice-shop:v19.0.0` to a local registry and signed it with Cosign. The signature was created for the image's **digest** (a unique SHA256 hash of the image content), not for the tag. This means:

- **Tag tampering protection:** If someone overwrites the image at the same tag (e.g., pushes a different image to `juice-shop:v19.0.0`), the digest changes. The original signature will not match the new content, and Cosign will report that the signature is invalid or missing for the new digest. This prevents attackers from silently replacing trusted images under the same tag.
- **Subject digest:** The subject digest is the immutable, content-addressed identifier of the image (e.g., `sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58`). It uniquely identifies the exact image content, regardless of what tag is used. All signature and attestation verification in Cosign is performed against this digest, ensuring integrity and authenticity of the image.

## Task 2 — Attestations: SBOM (reuse) & Provenance

### How attestations differ from signatures

A **signature** simply proves the integrity and authenticity of an artifact (such as a container image) by verifying that it has not been tampered with and was signed by a trusted party.  
An **attestation** is a signed statement that attaches additional metadata or claims to an artifact. Attestations can include information such as a Software Bill of Materials (SBOM), build provenance, security scan results, or policy compliance. While both are cryptographically signed, attestations provide richer context and evidence about the artifact’s origin and properties, not just its integrity.

---

### What information the SBOM attestation contains

The **SBOM attestation** (in CycloneDX format) contains a detailed inventory of all software components, libraries, and dependencies included in the container image. This includes:
- Component names and versions
- Licenses
- Hashes/checksums
- Supplier information
- Dependency relationships

This information helps consumers of the image understand exactly what is inside, assess vulnerabilities, and comply with supply chain transparency requirements.

---

### What provenance attestations provide for supply chain security

A **provenance attestation** documents how, when, and by whom the image was built. In this lab, the provenance attestation includes:
- The build type (manual-local-demo)
- The builder identity (e.g., `student@local`)
- The image reference and parameters used for the build
- The build start time (RFC3339 timestamp)
- Completeness information

Provenance attestations are critical for supply chain security because they provide traceability and accountability for each artifact. They help detect unauthorized or suspicious builds, support incident response, and enable automated policy enforcement for trusted builds.

---
## Task 3 — Artifact (Blob/Tarball) Signing

### Use cases for signing non-container artifacts

Signing non-container artifacts, such as tarballs, binaries, scripts, or configuration files, is important for ensuring their integrity and authenticity. Typical use cases include:
- Distributing release binaries or software updates, so users can verify the files were produced by the trusted publisher and have not been tampered with.
- Signing configuration files or scripts that are used in automated deployments, to prevent unauthorized changes or malicious injections.
- Providing cryptographic proof for any critical file exchanged between systems or teams.

---

### How blob signing differs from container image signing

Blob signing with Cosign is used for arbitrary files (not just container images). The main differences are:
- **Storage:** The signature (and bundle) for a blob is stored as a separate file (e.g., `.bundle`) alongside the artifact, rather than being attached to an image in a container registry.
- **Verification:** Verification is performed directly against the file and its signature, without involving a registry or digest reference.
- **Flexibility:** Blob signing works for any file type, making it suitable for a wide range of supply chain artifacts beyond container images.
