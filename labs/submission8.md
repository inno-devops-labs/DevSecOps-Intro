# Lab 8 - Software Supply Chain Security

## Scope
- Target image: `bkimminich/juice-shop:v19.0.0`
- Main tools: `cosign`, local Docker registry, `jq`, `syft`
- Local registry used in this run: `localhost:5001`

## Environment Notes
- Port `5000` was already occupied on this host by a macOS system process, so I used `localhost:5001` for the local registry. Evidence: `labs/lab8/analysis/registry-port-note.txt`
- `cosign` version in this environment is `v3.0.5` on `darwin/arm64`. Evidence: `labs/lab8/analysis/cosign-version.txt`
- `cosign` v3 required minor flag adjustments versus the lab text:
  - image signing used `--use-signing-config=false` together with `--allow-http-registry`
  - digest lookup from the registry had to accept OCI manifests as well as Docker manifests

## Task 1 - Local Registry, Signing, Verification, and Tamper Demo

### Generated Artifacts
- `labs/lab8/registry/pull-image.txt`
- `labs/lab8/registry/start-registry.txt`
- `labs/lab8/registry/push-local.txt`
- `labs/lab8/signing/generate-key-pair.txt`
- `labs/lab8/signing/cosign.pub`
- `labs/lab8/signing/sign.txt`
- `labs/lab8/signing/verify.txt`
- `labs/lab8/signing/verify-after-tamper.txt`
- `labs/lab8/signing/verify-original-after-tamper.txt`
- `labs/lab8/analysis/ref.txt`
- `labs/lab8/analysis/ref-after-tamper.txt`
- `labs/lab8/analysis/tamper-status.txt`

### Digest-Pinned References
- Original signed image:
  - `localhost:5001/juice-shop@sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5`
- After retagging `busybox:latest` onto the same mutable tag:
  - `localhost:5001/juice-shop@sha256:c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6`

### Verification Result
- Verification of the original digest succeeded: `labs/lab8/signing/verify.txt`
- Verification of the tampered digest failed with `no signatures found`: `labs/lab8/signing/verify-after-tamper.txt`
- Exit code for the tampered verification was `10`: `labs/lab8/analysis/tamper-status.txt`
- Verification of the original digest still succeeded after tag tampering: `labs/lab8/signing/verify-original-after-tamper.txt`

### Analysis
- Signing protects against tag tampering because Cosign signs the immutable manifest digest, not the mutable tag string.
- A tag like `juice-shop:v19.0.0` can be moved to point at a completely different manifest later, which is exactly what the tamper demo did.
- The `subject digest` is the exact OCI manifest hash that the signature or attestation refers to.
- Because the subject is the digest, verification succeeds only when the verifier checks the same manifest bytes that were originally signed.

## Task 2 - Attestations: SBOM and Provenance

### Generated Artifacts
- `labs/lab8/attest/juice-shop.cdx.json`
- `labs/lab8/attest/attest-sbom.txt`
- `labs/lab8/attest/verify-sbom-attestation.txt`
- `labs/lab8/attest/sbom-attestation-payload.json`
- `labs/lab8/attest/provenance.json`
- `labs/lab8/attest/attest-provenance.txt`
- `labs/lab8/attest/verify-provenance.txt`
- `labs/lab8/attest/provenance-attestation-payload.json`

### SBOM Attestation Findings
- The SBOM attestation verification succeeded.
- Decoded payload facts from `labs/lab8/attest/sbom-attestation-payload.json`:
  - `predicateType`: `https://cyclonedx.org/bom`
  - subject image: `localhost:5001/juice-shop`
  - subject digest: `772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5`
  - SBOM format: `CycloneDX`
  - component count: `3532`
  - image metadata component: `bkimminich/juice-shop` version `v19.0.0`

What the SBOM attestation contains:
- package/component inventory
- package versions and package URLs (`purl`)
- CPE hints
- license metadata
- image metadata and source labels

### Provenance Attestation Findings
- The provenance attestation verification succeeded.
- Decoded payload facts from `labs/lab8/attest/provenance-attestation-payload.json`:
  - builder id: `student@local`
  - build type: `manual-local-demo`
  - build timestamp: `2026-03-27T11:51:58Z`
  - invocation image parameter: the exact digest-pinned `localhost:5001/juice-shop@sha256:...` reference
- The verified attestation payload was normalized by Cosign to SLSA provenance `v0.2` predicate type, even though the locally authored input file used the newer `v1` style field. This is an observed tool/output detail, not a manual rewrite.

### Signatures vs Attestations
- A signature answers: "Was this exact artifact signed by the expected key?"
- An attestation answers: "What signed statement is attached to this exact artifact?"
- In practice:
  - the image signature proves integrity and signer identity for the digest
  - the SBOM attestation adds software inventory metadata
  - the provenance attestation adds build context metadata

### Supply Chain Value
- SBOM attestations help consumers audit dependencies, licenses, and vulnerable packages attached to the exact image digest they pull.
- Provenance attestations help answer where an artifact came from, who/what built it, and what build parameters were used.
- Together, digest signing plus attestations improve traceability, tamper resistance, and downstream trust decisions.

## Task 3 - Artifact (Blob/Tarball) Signing

### Generated Artifacts
- `labs/lab8/artifacts/sample.txt`
- `labs/lab8/artifacts/sample.tar.gz`
- `labs/lab8/artifacts/sample.tar.gz.bundle`
- `labs/lab8/artifacts/sign-blob.txt`
- `labs/lab8/artifacts/verify-blob.txt`

### Result
- The tarball was signed with `cosign sign-blob`.
- Verification with the public key and bundle succeeded: `Verified OK`

### Use Cases for Non-Container Artifact Signing
- release binaries
- tarballs and offline deliverables
- configuration bundles
- policy files
- Helm charts or generated deployment artifacts

### Blob Signing vs Image Signing
- Blob signing targets a file hash directly.
- Image signing targets an OCI image manifest digest stored in a registry.
- Blob verification usually works with a detached signature or bundle file.
- Image verification queries registry-stored signature artifacts attached to the image digest.

## Security and Repo Hygiene
- The private signing key `labs/lab8/signing/cosign.key` was intentionally excluded from version control via `labs/lab8/signing/.gitignore`.
- The public key `labs/lab8/signing/cosign.pub` is safe to commit and is required for verification evidence.

## Conclusion
- Task 1 completed: local registry push, digest-pinned signing, verification, and tamper demonstration all worked.
- Task 2 completed: both SBOM and provenance attestations were attached, verified, and decoded for inspection.
- Task 3 completed: a non-container artifact was signed and verified successfully.
- The lab demonstrates the core supply-chain model clearly:
  - verify by digest, not by tag
  - attach machine-readable metadata as attestations
  - keep private signing material out of the repository
