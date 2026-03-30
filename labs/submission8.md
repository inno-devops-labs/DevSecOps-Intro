# Lab 8 Submission — Supply Chain Signing & Attestations

## Lab context

- Target image: `bkimminich/juice-shop:v19.0.0`
- Local registry: `localhost:5000` (Docker Registry v3)
- Cosign version (binary used): `v3.0.5`
- Work directories:
  - Evidence/logs: `labs/lab8/**`

## Task 1 — Local Registry, Signing & Verification

### 1.1 Push image to local registry

Used the local registry digest reference from:

- `labs/lab8/analysis/ref.txt`
  - `localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48`

### 1.3 Sign and verify the image

Cosign signature verification succeeded using the generated key pair:

- Signing log: `labs/lab8/signing/sign.txt`
- Verification log: `labs/lab8/signing/verify.txt`

Key verification output confirms:

- Cosign claims were validated
- Signature was verified against the specified public key

Note: the verification logs include a warning about skipping transparency-log verification (`tlog`) for the lab/offline flow.

### 1.4 Tamper demonstration (signature should fail after digest change)

Tamper flow was executed by re-pushing the (retagged) content to the local registry and re-resolving the digest:

- After-tamper digest reference: `labs/lab8/analysis/ref-after-tamper.txt`
- Expected failure output: `labs/lab8/signing/verify-after-tamper.txt`
- Expected success sanity check output (original digest): `labs/lab8/signing/verify-original-after-tamper.txt`

Result:

- Verifying the “after tamper” digest fails (no valid signature found).
- Verifying the original signed digest succeeds.

### How signing protects against tag tampering + what “subject digest” means

- **Why tag tampering is blocked:** Cosign signs by **digest** (the immutable content identifier), not by tag. A tag can be moved to point at different content; however, the signature is bound to the digest. After tampering, the digest changes, so verification fails.
- **What “subject digest” means:** In the Cosign claims, the **subject** is the image identifier; for digest-based signing, that subject is the `sha256:<manifest-digest>` of the image in the registry. Verification compares the signature’s subject digest to the digest of the image being verified.

## Task 2 — Attestations (SBOM + Provenance)

### 2.1 SBOM attestation (CycloneDX)

SBOM conversion:

- CycloneDX SBOM JSON generated at: `labs/lab8/attest/juice-shop.cdx.json`
- Attestation creation log: `labs/lab8/attest/attest-sbom.txt`

Verification:

- Verification output (JSON): `labs/lab8/attest/verify-sbom-attestation.json`
- SBOM attestation verification payload was successfully decoded and inspected:
  - Decoded payload: `labs/lab8/attest/sbom-attestation-payload.json`
  - Predicated extracted: `labs/lab8/attest/sbom-predicate.json`
  - `predicateType` extracted as: `https://cyclonedx.org/bom` (see `labs/lab8/attest/sbom-predicate-type.txt`)

### 2.2 Simple provenance attestation (SLSA Provenance)

Created minimal provenance predicate JSON at:

- `labs/lab8/attest/provenance.json`

Attestation + verification:

- Attestation log: `labs/lab8/attest/attest-provenance.txt`
- Verification output (JSON): `labs/lab8/attest/verify-provenance.json`
- Decoded verification payload inspected:
  - Decoded payload: `labs/lab8/attest/provenance-attestation-payload.json`
  - `predicateType` extracted as: `https://slsa.dev/provenance/v0.2` (see `labs/lab8/attest/provenance-predicate-type.txt`)

### How attestations differ from signatures + what they contain/provide

- **Signatures vs attestations**
  - A **signature** proves that a signer approved a specific subject (here, the image digest).
  - An **attestation** attaches *structured evidence* (SBOM/provenance claims) to a subject digest, also protected by cryptographic integrity.
- **What the SBOM attestation contains**
  - A CycloneDX BOM predicate that enumerates components/dependencies for the image, which helps vulnerability assessment and dependency auditing.
- **What provenance attestations provide**
  - Provenance describes how/when/by whom the artifact was produced (e.g., build type, builder identity, build start timestamp, and parameters). This helps detect supply-chain tampering and supports policy checks on build workflow integrity.

## Task 3 — Artifact (Blob/Tarball) Signing

Target: non-container artifact `labs/lab8/artifacts/sample.tar.gz`

Attempted blob signing/verification with Cosign, but it failed in this environment due to Cosign’s dependency on Sigstore **TUF metadata fetching** (network/DNS restrictions).

- Evidence of failure:
  - `labs/lab8/artifacts/sign-blob-offline.txt`

Because this step could not complete, I cannot provide verified blob-signing outputs for Task 3 from this run.

## Acceptance Criteria (self-check)

- ✅ Task 1 — local registry push + Cosign signature + verify + tamper demo explained
- ✅ Task 2 — SBOM + provenance attestations created and verified; payload decoded and inspected with `jq`
- ❌ Task 3 — artifact blob signing/verification failed due to Cosign/TUF network access restrictions in the execution environment

