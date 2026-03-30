# Submission 8 — Supply Chain Security: Signing & Verification

## Task 1 — Local Registry, Signing & Verification
**Image Tag:** `localhost:5005/juice-shop:v19.0.0`
**Image Digest:** `sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5`

### 1. Verification of original (signed) image
Running the verification on the original digest was successful. 
Output snippet:
```
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

### 2. Tamper Demonstration
After mimicking an attack where `busybox:latest` was pushed to `localhost:5005/juice-shop:v19.0.0`, the registry resolved to a different digest (`sha256:c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6`).

**Explanation of how signing guards against tag tampering:**
Tags are mutable pointers that can be overwritten by anyone with push access. If a consumer pulls a container via a tag (e.g. `:v19.0.0`), they could unknowingly download compromised bits. By enforcing verification based on cryptographic signatures linked to the exact *digest*, we prevent tampering because the attacker doesn't possess the private key needed to sign the tampered digest.

**What "subject digest" means:**
The subject digest is the immutable cryptographic hash representing the exact payload of the image (or any artifact). It is the true identifier that Cosign references when signing and validating, rather than the mutable string tag.

---

## Task 2 — Attestations: SBOM & Provenance

### 1. Verification Outputs
- **CycloneDX Attestation Verification Output:** Saved to `labs/lab8/attest/verify-sbom-attestation.txt`
- **SLSA Provenance Verification Output:** Saved to `labs/lab8/attest/verify-provenance.txt`

### 2. Attestations vs Signatures
- **Signature:** Proves the basic origin and integrity of the artifact (i.e. "I signed this specific collection of bits").
- **Attestation:** A specialized form of signature containing structured *in-toto claims* about the software (the predicate). It goes beyond "I signed it" to state specific contextual metadata like "I built this image and here is the exact list of tools I used" or "Here is the exact vulnerability or license SBOM associated with it".

### 3. SBOM Attestation Contents
The CycloneDX SBOM attestation contains comprehensive data about the software components making up the container (e.g., node modules, distribution packages). It allows consumers or policy engines (like Kyverno or Cosigned) to cryptographically verify if the image meets policy requirements, such as restricting specific libraries or enforcing known safe versions.

### 4. Provenance Attestations
A SLSA provenance attestation gives undeniable supply chain evidence around the build environment. This asserts exactly who built it, the build timestamp, the parameters used, the origin repo, and the builder ID. When integrated correctly, this prevents tampering during the build/CI step by providing cryptographically verifiable lineage.

---

## Task 3 — Artifact (Blob) Signing

### 1. Artifact Verification Output
The local artifact (`sample.tar.gz`) was successfully signed using Cosign and verified.
Verification output snippet:
```
Verified OK
```

### 2. Use Cases for Signing Non-Container Artifacts
Many assets in a release pipeline exist outside containers:
- Configuration files / Terraform modules
- Native binary compilations (e.g. CLI tools like `.exe`, `.deb`, `.rpm`)
- Custom machine learning models or weight files
Signing them ensures downstream operators or internal infrastructure components can mathematically verify the source and integrity before loading/installing them.

### 3. Blob Signing vs Container Image Signing
Cosign signing a container leverages OCI registry standards to automatically store the signature as part of a reference tag near the original container in the registry. 
When signing *blobs* (like a tarball locally), the signature is typically detached and placed into a separate bundle file (e.g. `sample.tar.gz.bundle` or `.sig`). Distributing the blob requires passing along and checking the corresponding signature file simultaneously, rather than it naturally bundling up inside a container registry.