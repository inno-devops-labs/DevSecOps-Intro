# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

> **Student:** ellilin
> **Branch:** feature/lab8
> **Date:** 2026-03-31
> **Environment:** macOS + Docker Desktop 28.3.3 (`linux/arm64`) + `jq` 1.7.1 + Cosign v3.0.5

---

## Executive Summary

This lab implemented the full local supply-chain workflow for `bkimminich/juice-shop:v19.0.0`:

- mirrored the image into a local registry at `localhost:5000`
- signed the image by digest with Cosign
- verified the signature with the matching public key
- demonstrated tag tampering by overwriting the tag with `busybox`
- attached and verified two attestations:
  - CycloneDX SBOM
  - SLSA-style provenance
- signed and verified a non-container artifact (`sample.tar.gz`)

Primary image references used in the lab:

- Original signed local digest: `localhost:5000/juice-shop@sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5`
- Tampered tag digest after overwrite: `localhost:5000/juice-shop@sha256:c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6`

Important environment adjustments:

1. Cosign v3.0.5 deprecates the old lab-era `--tlog-upload=false` workflow. I used `--use-signing-config=false` together with the lab’s local-key workflow so the commands still worked against the local insecure registry.
2. `curl` to `localhost` required `--noproxy '*'` in this environment, because the default proxy settings returned `503` for loopback HTTP.
3. `cosign verify-blob` tried to create `~/.sigstore`, which is blocked by the workspace sandbox, so I set `HOME=/tmp` for blob verification.

Artifacts were created under `labs/lab8/`:

- `labs/lab8/analysis/ref.txt`
- `labs/lab8/analysis/ref-after-tamper.txt`
- `labs/lab8/analysis/cosign-tree.txt`
- `labs/lab8/analysis/verify-tampered.txt`
- `labs/lab8/analysis/verify-original-after-tamper.txt`
- `labs/lab8/signing/sign-image.txt`
- `labs/lab8/signing/verify-image.txt`
- `labs/lab8/attest/juice-shop.cdx.json`
- `labs/lab8/attest/verify-sbom-attestation.txt`
- `labs/lab8/attest/inspect-sbom.json`
- `labs/lab8/attest/provenance.json`
- `labs/lab8/attest/verify-provenance.txt`
- `labs/lab8/attest/inspect-provenance.json`
- `labs/lab8/artifacts/sign-blob.txt`
- `labs/lab8/artifacts/verify-blob.txt`

---

## Task 1 — Local Registry, Signing, Verification, and Tamper Demonstration

### 1.1 Local Registry Mirror

I pulled `bkimminich/juice-shop:v19.0.0`, started a local registry container (`registry:3`), and pushed the image as:

```text
localhost:5000/juice-shop:v19.0.0
```

Docker reported the pushed local manifest digest as:

```text
sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5
```

I used the immutable digest reference for all signing and attestation operations:

```text
localhost:5000/juice-shop@sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5
```

Evidence:

- `labs/lab8/analysis/ref.txt`

### 1.2 Cosign Key Pair

I generated a local key pair:

- `labs/lab8/signing/cosign.key`
- `labs/lab8/signing/cosign.pub`

The key pair was then used for image signing, attestation signing, and blob signing.

### 1.3 Image Signature Verification

Cosign verification succeeded for the original digest using the public key. The verification output confirmed:

- cosign claims were validated
- the signature matched the specified public key
- the signed identity and image manifest digest both pointed to the original digest

Evidence:

- `labs/lab8/signing/verify-image.txt`
- `labs/lab8/analysis/cosign-tree.txt`

The `cosign tree` output also showed three attached OCI referrers for the signed digest:

- one signature artifact (`https://sigstore.dev/cosign/sign/v1`)
- one CycloneDX attestation
- one SLSA provenance attestation

### 1.4 Tamper Demonstration

To simulate tag tampering, I replaced the mutable tag `localhost:5000/juice-shop:v19.0.0` with `busybox:latest` and pushed it to the same tag. That changed the digest behind the tag to:

```text
sha256:c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6
```

Verification results:

- verifying the new tampered digest failed with `no signatures found`
- verifying the original digest still succeeded

This is the core security property of digest-based signing: changing what a tag points to does not forge a valid signature for the new content.

Evidence:

- `labs/lab8/analysis/ref-after-tamper.txt`
- `labs/lab8/analysis/verify-tampered.txt`
- `labs/lab8/analysis/verify-original-after-tamper.txt`

### 1.5 Analysis

**How signing protects against tag tampering**

Container tags are mutable labels. An attacker or compromised registry workflow can repoint `v19.0.0` to different content without changing the tag string. When we sign by digest, Cosign binds the signature to the exact manifest digest, not to the mutable tag. If the tag later points to another image, the new digest does not have the original signature, so verification fails.

**What “subject digest” means**

The subject digest is the cryptographic identifier of the exact artifact being signed or attested. In this lab, the subject digest was the Juice Shop manifest digest:

```text
sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5
```

That digest is the identity of the artifact for verification purposes. If the artifact changes, the digest changes, and the original signature or attestation no longer applies.

---

## Task 2 — Attestations: SBOM and Provenance

### 2.1 SBOM Attestation

I reused the Syft native SBOM from Lab 4:

- source: `labs/lab4/syft/juice-shop-syft-native.json`

Then I converted it to CycloneDX JSON:

- output: `labs/lab8/attest/juice-shop.cdx.json`

File size:

- `2,231,669` bytes

I attached that SBOM as a Cosign attestation of type `cyclonedx` and verified it successfully with the public key.

Evidence:

- `labs/lab8/attest/juice-shop.cdx.json`
- `labs/lab8/attest/verify-sbom-attestation.txt`
- `labs/lab8/attest/inspect-sbom.json`

Decoded attestation inspection showed:

- statement type: `https://in-toto.io/Statement/v0.1`
- predicate type: `https://cyclonedx.org/bom`
- subject digest: `sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5`
- BOM format: `CycloneDX`
- spec version: `1.6`
- component count: `3532`
- root component: `bkimminich/juice-shop:v19.0.0`
- generator: `syft 1.42.1`

**How attestations differ from signatures**

A signature answers the question: “Was this exact artifact signed by the expected key?”  
An attestation answers: “What signed metadata is being asserted about this artifact?”

So:

- signature: authenticity and integrity of the artifact itself
- attestation: authenticity and integrity of metadata about the artifact

An attestation is still signed, but the signed payload contains structured claims such as an SBOM, provenance, scan result, or policy decision.

**What information the SBOM attestation contains**

The SBOM attestation contains a software inventory for the image, including:

- the subject image digest it applies to
- package/component identities
- versions
- metadata about the root container image
- tool metadata showing Syft as the generator
- dependency and file/package relationships encoded in CycloneDX

This makes the image contents inspectable and traceable without trusting an unsigned sidecar file.

### 2.2 Provenance Attestation

I created a minimal provenance predicate in:

- `labs/lab8/attest/provenance.json`

Then I attached it as a `slsaprovenance` attestation and verified it successfully.

Evidence:

- `labs/lab8/attest/provenance.json`
- `labs/lab8/attest/verify-provenance.txt`
- `labs/lab8/attest/inspect-provenance.json`

Decoded provenance inspection showed:

- statement type: `https://in-toto.io/Statement/v0.1`
- predicate type: `https://slsa.dev/provenance/v0.2`
- subject digest: `sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5`
- builder ID: `student@local`
- build type: `manual-local-demo`
- invocation parameter `image` set to the signed digest reference
- build start timestamp: `2026-03-31T15:05:19Z`

**What provenance attestations provide for supply chain security**

Provenance gives verifiable build context. It helps answer:

- who or what produced the artifact
- how it was built
- which parameters or inputs were used
- when the build occurred

That strengthens supply-chain trust because consumers can verify not only that an artifact was signed, but also that it came from an expected process or builder. In mature systems, provenance is a foundation for policy enforcement, reproducibility checks, and trusted build pipelines.

---

## Task 3 — Artifact (Blob/Tarball) Signing

I created a simple text file and packed it into:

- `labs/lab8/artifacts/sample.tar.gz`

SHA-256 of the tarball:

```text
b887fcf65b8a942db56064c66c6757cdb0bc3b32c46b0b4eafca8b336ec20fd5
```

I signed the tarball with `cosign sign-blob` and verified it successfully with `cosign verify-blob`.

Evidence:

- `labs/lab8/artifacts/sign-blob.txt`
- `labs/lab8/artifacts/verify-blob.txt`

Verification result:

```text
Verified OK
```

**Use cases for signing non-container artifacts**

Signing non-container artifacts is useful for:

- release binaries
- installation archives
- configuration bundles
- policy files
- SBOM documents
- Terraform or Kubernetes release packages

Any artifact distributed outside a container registry can still benefit from integrity and publisher verification.

**How blob signing differs from container image signing**

Blob signing signs a regular file directly. There is no registry manifest, tag, or OCI referrer graph involved. Verification checks the file bytes against a detached signature or bundle.

Container signing signs an OCI artifact identified by registry reference and digest. It integrates with registries and can store related signatures and attestations as OCI referrers attached to the image digest.

---

## Acceptance Criteria Check

- `labs/submission8.md` includes analysis and evidence for Tasks 1–3: **Yes**
- image pushed to local registry; Cosign signature created and verified: **Yes**
- tamper scenario demonstrated and explained: **Yes**
- SBOM and provenance attestations attached and verified; payload inspected with `jq`: **Yes**
- artifact signing performed and verified: **Yes**

No separate bonus task was present in `labs/lab8.md`, so the full required lab scope is complete.
