# Lab 8 - Software Supply Chain Security: Signing, Verification, and Attestations

## Scope

- Analysis date: `2026-04-06`
- Target image: `bkimminich/juice-shop:v19.0.0`
- Evidence root: `labs/lab8/`
- Tooling used in this environment:
  - Docker CLI + local registry (`registry:3`)
  - Cosign `v2.4.1` via container image (`ghcr.io/sigstore/cosign/cosign:v2.4.1`)
  - Syft via container image (`anchore/syft:latest`)

Environment note:
- Host binaries `cosign` and `jq` were not installed, so Cosign/SBOM work was executed from containers.
- Because Cosign ran in a container, verification/signing against local registry used `host.docker.internal:5000` (container reachability), while the host-side registry/tag workflow remained `localhost:5000`.

## Task 1 - Local Registry, Signing, Verification, Tamper Demo

### 1.1 Pull, local registry push, and digest references

Evidence:
- `labs/lab8/registry/pull-juice-shop.txt`
- `labs/lab8/registry/push-local-registry.txt`
- `labs/lab8/analysis/ref.txt`
- `labs/lab8/analysis/ref-cosign.txt`

Resolved original digest:
- Host ref: `localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58`
- Cosign container ref: `host.docker.internal:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58`

### 1.2 Key generation, signing, and verification

Evidence:
- `labs/lab8/signing/cosign-version.txt`
- `labs/lab8/signing/generate-key-pair.txt`
- `labs/lab8/signing/sign-image.txt`
- `labs/lab8/signing/verify-image-success.txt`

Result:
- Image signed successfully (`sign-image.txt` shows signature push).
- Signature verification succeeded (`verify-image-success.txt`, `EXIT=0`).

### 1.3 Tamper demonstration

Tamper action:
- Retagged/pushed `busybox:latest` onto `localhost:5000/juice-shop:v19.0.0`.

Evidence:
- `labs/lab8/registry/pull-busybox.txt`
- `labs/lab8/registry/push-tampered-tag.txt`
- `labs/lab8/analysis/ref-after-tamper.txt`
- `labs/lab8/signing/verify-image-tampered-fail.txt`
- `labs/lab8/signing/verify-image-original-still-valid.txt`

Resolved tampered digest:
- `localhost:5000/juice-shop@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65`

Verification behavior:
- Tampered digest verification failed as expected (`no signatures found`, `EXIT=10`).
- Original digest verification still succeeded (`EXIT=0`).

### 1.4 Explanation: tampering resistance and subject digest

- Signing protects against tag tampering because the signature binds to a **specific manifest digest**, not to a mutable tag string. If the same tag later points to different content, verification against the new digest fails.
- "Subject digest" is the cryptographic hash of the exact artifact (image manifest) that was signed/attested. It is the immutable identity used to prove "this exact byteset" was produced and approved.

## Task 2 - Attestations (SBOM and Provenance)

### 2.1 SBOM attestation (CycloneDX)

Evidence:
- `labs/lab8/attest/generate-syft-native.txt`
- `labs/lab8/attest/convert-to-cyclonedx.txt`
- `labs/lab8/attest/juice-shop.cdx.json`
- `labs/lab8/attest/attest-sbom.txt`
- `labs/lab8/attest/verify-sbom-attestation.txt`
- `labs/lab8/attest/sbom-payload-inspection.txt`

Payload inspection highlights:
- `payloadType=application/vnd.in-toto+json`
- `predicateType=https://cyclonedx.org/bom`
- `subjectDigest=547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58`
- `bomFormat=CycloneDX`
- `specVersion=1.6`
- `componentCount=3533`

### 2.2 Provenance attestation (SLSA provenance)

Evidence:
- `labs/lab8/attest/provenance.json`
- `labs/lab8/attest/attest-provenance.txt`
- `labs/lab8/attest/verify-provenance.txt`
- `labs/lab8/attest/provenance-payload-inspection.txt`

Payload inspection highlights:
- `payloadType=application/vnd.in-toto+json`
- `predicateType=https://slsa.dev/provenance/v0.2`
- `subjectDigest=547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58`
- `builderId=student@local`
- `buildType=manual-local-demo`
- `buildStartedOn=2026-04-06T17:54:54Z`

### 2.3 Analysis: signatures vs attestations

- Signature answers: "Was this artifact signed by the expected key?"
- Attestation answers: "What metadata claims are attached to this artifact?" (e.g., SBOM contents, build provenance).
- SBOM attestation provides software composition context (components, versions, package identities) that supports vulnerability management and license/compliance workflows.
- Provenance attestation provides build context (builder identity, build type, invocation metadata/timestamp), improving traceability and helping detect unauthorized or untrusted build paths.

## Task 3 - Artifact (Blob/Tarball) Signing

### 3.1 Blob signing and verification

Evidence:
- `labs/lab8/artifacts/sample.txt`
- `labs/lab8/artifacts/sample.tar.gz`
- `labs/lab8/artifacts/sign-blob.txt`
- `labs/lab8/artifacts/sample.tar.gz.bundle`
- `labs/lab8/artifacts/verify-blob.txt`

Result:
- Blob signing succeeded (`sign-blob.txt`, bundle created, `EXIT=0`).
- Blob verification succeeded (`verify-blob.txt`, `Verified OK`, `EXIT=0`).

### 3.2 Use cases and difference from image signing

Use cases for non-container artifact signing:
- Release binaries
- Tarballs/archives
- IaC bundles
- Configuration packages and policy bundles

Difference vs image signing:
- Container signing signs OCI-referenced artifacts in registry context (digest-addressed image manifests and related objects).
- Blob signing signs standalone files directly and verifies file integrity/signature against key/bundle, independent of OCI registry semantics.

## Outputs Produced

- Registry/signing evidence under:
  - `labs/lab8/registry/`
  - `labs/lab8/signing/`
- Attestation evidence under:
  - `labs/lab8/attest/`
- Digest/reference analysis under:
  - `labs/lab8/analysis/`
- Artifact signing evidence under:
  - `labs/lab8/artifacts/`

## Security Handling Note

- Private signing key is intentionally excluded from git tracking via `labs/lab8/signing/.gitignore` (`cosign.key`).
