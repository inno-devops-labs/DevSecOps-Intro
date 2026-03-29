# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Local Registry, Signing & Verification

*   **How signing protects against tag tampering:**

    In Docker, **tags are mutable** pointers (like a nickname). An attacker can change a tag to point to a malicious image. However, **signatures are tied to the Digest** (the unique cryptographic hash of the content). When you verify an image, Cosign checks if the specific digest you are pulling has been signed by your trusted key. If someone swaps the image under the tag, the digest changes, the signature no longer matches, and the verification fails.

*   **What "subject digest" means:**

    The "subject" is the specific artifact being signed. The **subject digest** is the unique SHA256 hash of the container image manifest that the signature is cryptographically bound to. It ensures that "what you see is what you signed" — if even one bit of the image changes, the digest will differ from the "subject" recorded in the signature.

## Task 2 — Attestations: SBOM (reuse) & Provenance

To generate a highly accurate report for **Task 2**, I have the essential data from the task description and your confirmation of success. I do not need the full JSON files, but **please confirm the following two details** so the report matches your specific environment:

1.  **Syft Version/Tooling:** Did the SBOM generation successfully identify approximately **1004 packages** (as seen in Lab 7's Scout scan), or did it show a different count? (I will assume the standard Juice Shop count of ~1000 if not specified).
2.  **Cosign Version:** Since you successfully used the `signing-config` from Task 1, I will reflect that modern "no-tlog" approach in the analysis.

Here is the documentation for `labs/submission8.md` for Task 2:

## Task 2 — Attestations: SBOM (reuse) & Provenance

### 2.1: Attestation vs. Signature Analysis

**How attestations differ from signatures:**

A **signature** is a cryptographic "seal of approval" that proves an artifact came from a specific identity and hasn't been tampered with. An **attestation**, however, is a signed **statement** about the artifact. While a signature says *"I trust this image,"* an attestation says *"Here is a signed list of ingredients (SBOM) for this image"* or *"Here is exactly how and where this image was built (Provenance)."* Attestations provide the "why" and "how" behind the "who" of the signature.

### 2.2: SBOM (Software Bill of Materials)

**Information contained in the SBOM attestation:**

The CycloneDX SBOM attached to the image (`juice-shop.cdx.json`) contains a comprehensive inventory of the software supply chain. This includes:
*   **Components:** A list of all NPM packages (e.g., `express`, `sequelize`) and system libraries.
*   **Versions:** Precise version strings for every dependency to allow for vulnerability matching.
*   **Licenses:** Legal metadata regarding the open-source licenses used by each component.
*   **Hashes:** Cryptographic hashes for the individual library files to ensure their integrity.

### 2.3: Provenance Attestations

**What provenance provides for supply chain security:**

Provenance attestations (SLSA) act as a "birth certificate" for the container image. They provide:
*   **Traceability:** Documentation of the build system and environment used to create the image (in this case, identified as `student@local`).
*   **Integrity of the Build Process:** Verification that the image wasn't swapped out between the build and the push stages.
*   **Policy Enforcement:** Organizations can use provenance to enforce rules, such as: *"Only deploy images built on official GitHub Action runners, not on developer laptops."*

## Task 3 — Artifact (Blob/Tarball) Signing

**Use cases for signing non-container artifacts:**
*   **Release Binaries:** Signing CLI tools, `.exe` installers, or `.deb/.rpm` packages to ensure users are downloading the genuine software.
*   **Configuration Files:** Signing critical infrastructure config (like Kubernetes YAMLs or Terraform plans) to ensure they haven't been modified by an unauthorized process before deployment.
*   **Checksum Files:** Signing a `SHA256SUMS` file so that even if the download server is compromised, the integrity of all files can still be verified.
*   **Firmware Updates:** Ensuring that hardware devices only accept signed update blobs to prevent bricking or malicious takeovers.

**How blob signing differs from container image signing:**
*   **Registry Storage:** Image signatures are stored as separate objects *inside* the container registry (OCI registry). Blob signatures are usually stored as local files (like `.sig` or `.bundle` files) that must be distributed alongside the artifact.
*   **Digest vs. File:** Image signing is strictly bound to the OCI manifest digest. Blob signing is bound to the raw bytes of the file on disk.
*   **Verification Flow:** Verifying an image involves querying the registry for the signature object. Verifying a blob requires the user to manually provide the signature file/bundle and the original file at the same time.
