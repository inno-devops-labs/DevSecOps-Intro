# Lab 8 — Image Signing, Verification, and Attestations

## Task 1 — Container Image Signing and Tag Tampering Demo

**Registry:** `localhost:5000`  
**Image:** `juice-shop:v19.0.0`

### Evidence

**Digest reference (before tamper):**
```
localhost:5000/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7
```

**Public key used for verification:**
```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcwRY765qYzO1v0cTwHJrHNKejHIg
Gj0TlSWoO2AF5hwQNjtIdNsCR+DE9nlDadmr7ekyxJk12waFThCU4GcX/A==
-----END PUBLIC KEY-----
```

**Verify (original digest) — PASS:**
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.

Verification for localhost:5000/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7"},"image":{"docker-manifest-digest":"sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

**Digest reference (after tamper):**

```
localhost:5000/juice-shop@sha256:4d27946a237962fbfdb74d11af6304f6495d5ce88d8386b28de8fa4cf7b23383
```

**Verify (tampered digest) — FAIL:**
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Explanation

A tag is a movable label and may point to different content over time. A digest (`sha256:…`) is a cryptographic fingerprint of the image’s manifest and content. Cosign signs and verifies the digest, not the tag. After retagging `juice-shop:v19.0.0` to a different image, the digest changed, so the original signature no longer matched and verification failed for the tampered digest while still passing for the original one.

## Task 2 — Attestations (SBOM and Provenance)

### How attestations differ from signatures

- **Signature:** proves integrity and authenticity of the exact artifact (the digest). Answers “Is this the same artifact that was approved?”
- **Attestation:** a signed statement with structured facts about that artifact (e.g., components list, build details, policy/test results). It adds context and traceability but does not replace signature-based integrity.

### SBOM attestation (CycloneDX)

**Verified attestation output (excerpt):**
```
(see file: labs/lab8/attest/verify-sbom-attestation.txt)
```

**Decoded predicate (excerpt from `juice-shop.cdx.json`):**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": "2026-03-07T07:43:18Z",
    "component": {
      "type": "container",
      "name": "localhost:5000/juice-shop",
      "version": "sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7"
    },
    "properties": [
      {"name": "org.opencontainers.image.title", "value": "OWASP Juice Shop"},
      {"name": "org.opencontainers.image.version", "value": "19.0.0"},
      {"name": "org.opencontainers.image.licenses", "value": "MIT"}
    ]
  },
  "components": [
    {"name": "1to2", "version": "1.0.0"},
    {"name": "@babel/parser", "version": "7.28.3"},
    {"name": "@nlpjs/core", "version": "4.26.1"},
    {"name": "@colors/colors", "version": "1.6.0"}
  ]
}
```

**What the SBOM attestation contains:** the image identity (by digest), creation metadata, license information, and a component inventory (packages, versions). This enables dependency and license audits and supports vulnerability analysis.

### Provenance attestation (SLSA)

**Verified attestation output (excerpt):**
```
(see file: labs/lab8/attest/verify-provenance.txt)
```

**Decoded predicate (excerpt from `provenance.json`):**
```json
{
  "_type": "https://slsa.dev/provenance/v1",
  "buildType": "manual-local-demo",
  "builder": {"id": "student@local"},
  "invocation": {
    "parameters": {
      "image": "localhost:5000/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7"
    }
  },
  "metadata": {
    "buildStartedOn": "2026-03-07T09:29:14Z",
    "completeness": {"parameters": true}
  }
}
```

**What provenance provides for supply chain security:** links the attestation to the exact digest and records who built it, when, and with which parameters. This supports source traceability, detection of unauthorized builds, and adherence to supply-chain standards (e.g., SLSA).

## Task 3 — Blob Signing (Non‑container Artifacts)

**Signed artifact:** `sample.tar.gz`  
**Signature bundle:** `sample.tar.gz.bundle`

**Verify output:**
```
Verified OK
```

### Use cases for signing non‑container artifacts

- Release deliverables and update archives (.zip, .tar.gz, .exe) to ensure downloads are authentic.
- Configuration and policy files (YAML/JSON, IaC templates) to prevent tampering with deployment settings.
- Data science and ML assets (models, datasets) to protect pipeline integrity.
- Source archives for reproducible releases.

### How blob signing differs from container image signing

- Target: any file versus an OCI image.
- Storage: blob signatures are kept in a local bundle file; image signatures are stored alongside the image digest in the registry.
- Verification reference: blob verification uses the file and its bundle; image verification uses the image’s digest reference.
- Primary use: securing artifacts distributed outside registries versus securing deployable container images.
