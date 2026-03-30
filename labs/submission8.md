# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations


## Task 1 — Local Registry, Signing & Verification

### Execution Summary

- Local registry started as `registry:3` on `localhost:5000`.
- Image was pushed to local registry and pinned by digest:
  - Original digest ref: `localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48`
- Cosign key pair generated and used to sign the original digest.
- Signature verification succeeded for the original digest.
- Tag tampering was simulated by overwriting `localhost:5000/juice-shop:v19.0.0` with `busybox:latest`.
  - New digest ref after tamper: `localhost:5000/juice-shop@sha256:11f85134f388cff5f4c66f9bb4c5942249c1f6f7eb8b3889948d953487b5f7a8`
- Verification failed for the tampered digest (`exit code 10`, `no signatures found`) and still succeeded for the original digest.

### Analysis: Why Signing Protects Against Tag Tampering

Container tags are mutable pointers, so `:v19.0.0` can be re-pointed to different content over time. Cosign signatures are bound to an immutable digest (the exact content hash), not just a human-readable tag. That means if a tag is overwritten with malicious/other content, verification of the new digest fails unless that exact new digest was signed by the trusted key.

### Analysis: What “Subject Digest” Means

The subject digest is the cryptographic hash (`sha256:...`) of the exact artifact/image manifest that was signed or attested. It uniquely identifies content and is immutable, which is why secure verification should always use digest references.

### Evidence

- `labs/lab8/registry/docker-pull-juice-shop.txt`
- `labs/lab8/registry/registry-run.txt`
- `labs/lab8/registry/docker-tag-juice-shop.txt`
- `labs/lab8/registry/docker-push-juice-shop.txt`
- `labs/lab8/analysis/ref.txt`
- `labs/lab8/signing/generate-key-pair.txt`
- `labs/lab8/signing/sign-image.txt`
- `labs/lab8/signing/verify-original.txt`
- `labs/lab8/registry/docker-pull-busybox.txt`
- `labs/lab8/registry/docker-tag-busybox-overwrite.txt`
- `labs/lab8/registry/docker-push-busybox-overwrite.txt`
- `labs/lab8/analysis/ref-after-tamper.txt`
- `labs/lab8/signing/verify-after-tamper.txt`
- `labs/lab8/signing/verify-after-tamper-exit.txt`
- `labs/lab8/signing/verify-original-post-tamper.txt`

---

## Task 2 — Attestations (SBOM + Provenance)

### Execution Summary

- Reused Lab 4 Syft-native SBOM (`labs/lab4/syft/juice-shop-syft-native.json`).
- Converted to CycloneDX JSON and attached as a `cyclonedx` attestation.
- Created and attached a SLSA provenance attestation (`slsaprovenance`).
- Verified both attestation types with Cosign.
- Decoded attestation payloads with `jq` to inspect the envelope content.

### Analysis: Signatures vs Attestations

- Signature: proves publisher key signed a specific artifact digest (authenticity + integrity).
- Attestation: signed structured metadata *about* that artifact digest (e.g., SBOM, provenance).

So attestations extend trust from “who signed this artifact” to “what do we know about how/what this artifact contains.”

### Analysis: What the SBOM Attestation Contains

The SBOM attestation contains CycloneDX software inventory data for the signed image digest, including packages/components, versions, and metadata. In this run, payload inspection confirms:

- `predicateType`: `https://cyclonedx.org/bom`
- `subject.name`: `localhost:5000/juice-shop`
- `subject.digest.sha256`: `b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48`

### Analysis: What Provenance Attestations Provide

Provenance attestations provide build context and origin metadata (builder identity, build type, invocation parameters, timestamp/completeness). This strengthens supply chain security by enabling policy checks such as trusted builder, expected build flow, and traceability from artifact back to build process.

In this run, payload inspection confirms:

- `predicateType`: `https://slsa.dev/provenance/v0.2`
- `subject.digest.sha256`: `b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48`
- `buildStartedOn`: `2026-03-29T20:13:39Z`

### Evidence

- `labs/lab8/attest/syft-reuse.txt`
- `labs/lab8/attest/syft-convert-cdx.txt`
- `labs/lab8/attest/juice-shop.cdx.json`
- `labs/lab8/attest/attest-sbom.txt`
- `labs/lab8/attest/verify-sbom-attestation.txt`
- `labs/lab8/attest/sbom-attestation-payload.json`
- `labs/lab8/attest/provenance.json`
- `labs/lab8/attest/attest-provenance.txt`
- `labs/lab8/attest/verify-provenance.txt`
- `labs/lab8/attest/provenance-attestation-payload.json`
- `labs/lab8/analysis/provenance-payload-summary.txt`

---

## Task 3 — Artifact (Blob/Tarball) Signing

### Execution Summary

- Created a sample text file and packed it as `sample.tar.gz`.
- Signed the tarball with `cosign sign-blob` and generated a bundle.
- Verified the tarball signature successfully using public key + bundle.

### Analysis: Use Cases for Signing Non-Container Artifacts

Examples:

- Release binaries (CLI tools, installers)
- Configuration bundles
- Model files/data artifacts
- SBOM files and security reports

Blob signing gives integrity/authenticity guarantees for artifacts that are not container images.

### Analysis: Blob Signing vs Container Image Signing

- Blob signing targets standalone files by path/hash.
- Container image signing targets OCI image digests in a registry.
- Image signatures are tied to registry artifacts and workflows; blob signatures are registry-agnostic and ideal for generic file distribution.

### Evidence

- `labs/lab8/artifacts/sample.txt`
- `labs/lab8/artifacts/sample.tar.gz`
- `labs/lab8/artifacts/sample.tar.gz.bundle`
- `labs/lab8/artifacts/sign-blob.txt`
- `labs/lab8/artifacts/verify-blob.txt`

---

## Tooling Evidence

- `labs/lab8/analysis/cosign-version.txt`
