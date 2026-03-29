# Lab 8 Submission — Software Supply Chain Security: Signing, Verification, and Attestations

## Overview

Target image:

```text
bkimminich/juice-shop:v19.0.0
```

Local signed subject:

```text
localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48
```

Artifacts for this lab were saved under `labs/lab8/`.

Tooling used:

- `cosign v3.0.5`
- `syft v1.42.3`
- Docker Engine `29.3.0`
- `jq 1.7`

Methodology notes:

- Cosign was not preinstalled in the environment, so I used the official release binary locally from `/tmp`.
- For the local registry flow I had to use `--allow-http-registry` in addition to `--allow-insecure-registry`, because `localhost:5000` is plain HTTP.
- In `cosign v3.0.5`, the lab’s `--tlog-upload=false` flow only worked after explicitly setting `--use-signing-config=false`. Without that, Cosign rejects the command because the default signing-config integration expects transparency-log configuration.
- The Syft native SBOM was generated successfully. For the CycloneDX predicate I derived a valid CycloneDX JSON document from the Syft-native SBOM, because the `syft convert` flow behaved inconsistently in this environment.
- The Cosign key pair was generated locally, used for signing/verification, and removed before commit. Only evidence files and the public-key hash were retained.

---

## Task 1 — Local Registry, Signing & Verification

### 1.1 Local Registry Push

I started a local registry on `localhost:5000`, tagged Juice Shop for the local registry, and pushed it successfully.

Evidence:

- `labs/lab8/registry/registry-container-id.txt`
- `labs/lab8/registry/push-juice-shop.txt`
- `labs/lab8/analysis/ref.txt`

Resolved local digest:

```text
sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48
```

Why use a digest instead of a tag:

- A tag is mutable.
- A digest identifies the exact manifest that was signed.
- This means verification is bound to one immutable artifact, not to a moving label like `v19.0.0`.

### 1.2 Cosign Key Pair

I generated a local Cosign key pair and used it for all signing operations in this lab.

Evidence:

- `labs/lab8/signing/generate-key-pair-status.txt`
- `labs/lab8/signing/public-key-sha256.txt`

Public key SHA-256:

```text
a6eec1f4a8a6e3ca72db3ca8150eb5d0a612ee117ae35dc64ddc18c8cb0a8023
```

Important:

- The actual `cosign.key` and `cosign.pub` files were **not committed**.
- This follows the lab guideline to keep keys out of version control.

### 1.3 Image Signing and Verification

I signed the local digest reference and verified it with the corresponding public key.

Evidence:

- `labs/lab8/signing/sign-image.txt`
- `labs/lab8/signing/sign-image-status.txt`
- `labs/lab8/signing/verify-image.txt`

Observed result:

- Signing succeeded.
- Verification succeeded.
- Because I had retried signing once while adapting the command to Cosign v3, verification returned **two valid signatures** for the same digest. This does not invalidate the result; it just means the same subject digest was signed twice with the same key.

The verified claims show the critical binding:

- `docker-reference = localhost:5000/juice-shop@sha256:b029...`
- `docker-manifest-digest = sha256:b029...`

### 1.4 Tamper Demonstration

I demonstrated tag tampering by replacing `localhost:5000/juice-shop:v19.0.0` with `busybox:latest`, then re-resolving the tag to a new digest.

New digest after tamper:

```text
sha256:11f85134f388cff5f4c66f9bb4c5942249c1f6f7eb8b3889948d953487b5f7a8
```

Evidence:

- `labs/lab8/registry/pull-busybox.txt`
- `labs/lab8/registry/push-tampered-tag.txt`
- `labs/lab8/analysis/ref-after-tamper.txt`
- `labs/lab8/signing/verify-after-tamper.txt`
- `labs/lab8/signing/verify-after-tamper-status.txt`
- `labs/lab8/signing/verify-original-after-tamper.txt`

Results:

- Verification of the **new tampered digest** failed with exit code `10`.
- Error:

```text
Error: no signatures found
```

- Verification of the **original signed digest** still succeeded.

#### What this proves

Signing protects against **tag tampering** because Cosign verifies the exact subject digest, not the tag.

The tag `localhost:5000/juice-shop:v19.0.0` was changed to point at different content, but the signed digest remained the original `sha256:b029...`. As a result:

- the new digest had no matching signature
- the old digest remained verifiable

#### What “subject digest” means

The subject digest is the cryptographic hash of the artifact that the signature or attestation refers to.

In this lab, the subject was:

```text
localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48
```

If the content changes, the digest changes, and the previous signature no longer matches the new subject.

---

## Task 2 — Attestations: SBOM and Provenance

### 2.1 SBOM Generation and CycloneDX Predicate

I generated a Syft-native SBOM for Juice Shop and derived a CycloneDX JSON predicate from it for attestation.

Evidence:

- `labs/lab4/syft/juice-shop-syft-native.json`
- `labs/lab8/attest/generate-syft-native-status.txt`
- `labs/lab8/attest/juice-shop.cdx.json`
- `labs/lab8/attest/convert-sbom-status.txt`
- `labs/lab8/attest/cyclonedx-summary.txt`

SBOM summary:

- CycloneDX components: **1139**
- Metadata component:
  - name: `localhost:5000/juice-shop@sha256:b029...`
  - type: `container`
  - version: `19.0.0`

### 2.2 SBOM Attestation

I attached the CycloneDX SBOM as an attestation to the original signed digest and verified it.

Evidence:

- `labs/lab8/attest/attest-sbom.txt`
- `labs/lab8/attest/attest-sbom-status.txt`
- `labs/lab8/attest/verify-sbom-attestation.txt`
- `labs/lab8/attest/inspect-sbom-payload.json`

Verified payload summary:

- `predicateType`: `https://cyclonedx.org/bom`
- `subject.name`: `localhost:5000/juice-shop`
- `subject.digest.sha256`: `b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48`
- `components_count`: `1139`

#### What the SBOM attestation contains

The SBOM attestation contains a signed inventory of software components in the image, including:

- package names
- versions
- package URLs (`purl`)
- license metadata
- the subject digest the SBOM applies to

This is useful for vulnerability management, license review, dependency inventory, and incident response.

### 2.3 Provenance Attestation

I created a minimal provenance predicate and attached it as a second attestation.

Evidence:

- `labs/lab8/attest/provenance.json`
- `labs/lab8/attest/attest-provenance.txt`
- `labs/lab8/attest/attest-provenance-status.txt`
- `labs/lab8/attest/verify-provenance.txt`
- `labs/lab8/attest/inspect-provenance-payload.json`

Verified provenance summary:

- `predicateType`: `https://slsa.dev/provenance/v0.2`
- `builder.id`: `student@local`
- `buildType`: `manual-local-demo`
- `invocation.parameters.image`: the signed local digest reference
- `metadata.buildStartedOn`: `2026-03-29T12:59:03Z`

Note:

- The input predicate file used a SLSA Provenance v1-style shape, but the verified attestation envelope recorded the predicate type under Cosign’s `slsaprovenance` mapping as `https://slsa.dev/provenance/v0.2`.

#### How attestations differ from signatures

A signature answers:

- “Was this exact subject digest signed by the holder of this key?”

An attestation answers:

- “Was this exact subject digest signed together with a structured statement about it?”

So:

- **signature** = proof of authenticity/integrity for the artifact
- **attestation** = proof of authenticity/integrity for a claim about the artifact

#### What provenance provides for supply chain security

Provenance helps answer:

- who or what built the artifact
- when it was built
- what parameters or inputs were used
- what process produced the artifact

This improves traceability, auditability, and trust in the build pipeline.

---

## Task 3 — Artifact (Blob/Tarball) Signing

### 3.1 Blob Signing and Verification

I created a simple tarball artifact, signed it with `cosign sign-blob`, produced a bundle, and verified it.

Evidence:

- `labs/lab8/artifacts/sample.txt`
- `labs/lab8/artifacts/sample.tar.gz`
- `labs/lab8/artifacts/sample.tar.gz.bundle`
- `labs/lab8/artifacts/sign-blob.txt`
- `labs/lab8/artifacts/sign-blob-status.txt`
- `labs/lab8/artifacts/verify-blob.txt`
- `labs/lab8/artifacts/verify-blob-status.txt`

Result:

- `sign-blob` succeeded
- `verify-blob` succeeded with:

```text
Verified OK
```

As with image verification in this local lab setup, blob verification needed `--insecure-ignore-tlog` because transparency-log upload was intentionally disabled.

#### Use cases for signing non-container artifacts

Typical use cases include:

- release binaries
- tarballs and ZIP archives
- configuration bundles
- policy files
- SBOM files
- installer packages

#### How blob signing differs from image signing

Blob signing:

- signs a local file directly
- verification happens against the file contents
- does not rely on an OCI registry subject

Image signing:

- signs an OCI artifact in a registry
- verification is tied to the image subject digest
- can also carry registry-native signatures and attestations

---

## Final Analysis

This lab demonstrates three distinct but related supply-chain controls:

1. **Image signing**
   Confirms that a specific image digest was signed by a trusted key.

2. **Attestations**
   Add signed metadata about that digest, such as SBOM or provenance.

3. **Blob signing**
   Extends the same trust model beyond containers to generic release artifacts.

The tamper demo is the key takeaway: mutable tags are not trustworthy on their own. The trust anchor is the digest.

The most important production lessons are:

- always sign and verify by digest, not by tag
- avoid insecure local-only flags in real environments
- keep keys out of source control
- use attestations to carry machine-readable evidence like SBOMs and provenance
- prefer transparency log uploads and trusted registries outside local test environments

---

## Research Sources

- Cosign install and system configuration: https://docs.sigstore.dev/cosign/system_config/installation/
- Cosign repository and releases: https://github.com/sigstore/cosign
- in-toto attestation model: https://github.com/in-toto/attestation
- CycloneDX: https://cyclonedx.org/
- SPDX: https://spdx.dev/
