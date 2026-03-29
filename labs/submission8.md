# Cosign Signing & Attestations Report

## 1. How Signing Protects Against Tag Tampering

Container image tags (e.g., `v19.0.0`, `latest`) are **mutable**. This means:
- A tag can be reassigned to a completely different image.
- An attacker (or mistake) could replace a trusted image with a malicious one.

### How signing helps

Cosign signs the **digest**, not the tag.

- Tag → pointer (mutable)
- Digest → content hash (immutable)

When you sign:
```
localhost:5000/juice-shop@sha256:547bd3fef4a6...
```

You are cryptographically binding:
- the image content
- to your identity (via your key)

### Protection mechanism

If someone tampers with the tag:
```
v19.0.0 → new malicious digest (e.g., sha256:b8d1827e...)
```

Verification will fail because:
- signature was created for the original digest
- digest has changed → signature mismatch

---

## 2. What “Subject Digest” Means

The **subject digest** is:

> The exact immutable identifier (hash) of the artifact being signed or attested.

Example:
```
sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58
```

### Key idea

- It uniquely represents the artifact content
- Any change → new digest
- Signatures and attestations are always tied to this digest

---

## 3. How Attestations Differ from Signatures

### Signatures
- Prove **authenticity and integrity**
- Answer: *“Was this artifact signed by a trusted key?”*

### Attestations
- Provide **structured metadata about the artifact**
- Answer: *“What is inside this artifact?” or “How was it built?”*

### Summary

| Feature        | Signature | Attestation |
|----------------|----------|-------------|
| Purpose        | Integrity & authenticity | Metadata & context |
| Content        | Cryptographic signature | JSON payload |
| Example        | Image signed with key | SBOM, provenance |

---

## 4. What Information SBOM Attestation Contains

An SBOM (Software Bill of Materials) includes:

- List of all dependencies
- Package names and versions
- Licenses
- File hashes
- Dependency relationships

### Why it matters

- Detect vulnerable components
- Ensure compliance (licenses)
- Improve transparency

---

## 5. What Provenance Attestations Provide

Provenance describes **how the artifact was built**.

Typical contents:
- Build system (CI/CD pipeline)
- Source repository and commit
- Build steps and parameters
- Builder identity

### Supply chain benefits

- Prevents tampering in build pipeline
- Enables reproducibility
- Verifies trusted build sources

---

## 6. Use Cases for Signing Non-Container Artifacts

Cosign can sign:

- Release binaries (e.g., `.tar.gz`, `.exe`)
- Configuration files (YAML, JSON)
- Scripts
- Machine learning models

### Examples

- Verify downloaded CLI tools
- Ensure config files weren’t modified
- Secure software distribution pipelines

---

## 7. Blob Signing vs Container Image Signing

### Container Image Signing
- Works with registries
- Signs image manifest digest
- Stored alongside image in registry

### Blob Signing
- Works on arbitrary files
- No registry required
- Signature stored separately

### Key differences

| Feature              | Image Signing | Blob Signing |
|----------------------|--------------|--------------|
| Storage              | Registry     | Local/anywhere |
| Target               | Image digest | File hash |
| Use case             | Containers   | Generic artifacts |

---

## 8. Observed Digests in This Lab

### Original (correct) digest
```
localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58
```

### After tampering
```
localhost:5000/juice-shop@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65
```

### Explanation

- The digest changed → content changed
- Original signature no longer valid
- Demonstrates protection against tampering

---

## 9. Conclusion

- Tags are mutable and unsafe for trust decisions
- Digests are immutable and must be used for signing
- Cosign ensures integrity by binding signatures to digests
- Attestations extend this by providing rich metadata
- Together, they form a strong foundation for supply chain security
