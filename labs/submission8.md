# Lab 8 — Submission

## Student
- Name: TODO
- Group: TODO
- Repository: TODO
- PR link: TODO

## Environment
- OS: Windows
- Shell: PowerShell
- Container runtime: Docker Desktop
- Registry: local registry on `localhost:5000`
- Signing tool: Cosign
- SBOM tool: Syft
- JSON processing: jq

## Goal
This lab demonstrates local container image signing and verification with Cosign, attachment and verification of attestations (SBOM and provenance), and signing of a non-container artifact. The workflow was adapted to Windows/PowerShell.

---

## Task 1 — Local Registry, Signing & Verification

### What I did
1. Pulled the target image `bkimminich/juice-shop:v19.0.0`.
2. Started a local registry at `localhost:5000`.
3. Tagged and pushed the image to the local registry.
4. Resolved the digest from the local registry and used the immutable digest reference for signing.
5. Generated a Cosign key pair and signed the image with the private key.
6. Verified the signature with the public key.
7. Demonstrated tag tampering by overwriting `localhost:5000/juice-shop:v19.0.0` with `busybox:latest`.
8. Re-resolved the digest after tampering and verified that the tampered digest failed verification, while the original digest still verified successfully.

### Evidence
- Original digest reference: `labs/lab8/analysis/ref.txt`
- Signature verification output: `labs/lab8/analysis/verify-image.txt`
- Digest reference after tampering: `labs/lab8/analysis/ref-after-tamper.txt`
- Tampered verification failure: `labs/lab8/analysis/verify-tampered.txt`
- Original digest still valid after tampering: `labs/lab8/analysis/verify-original-after-tamper.txt`

### Analysis
Signing protects against tag tampering because the signature is bound to the image digest, not to a mutable tag. A tag such as `juice-shop:v19.0.0` can be repointed to a different image, but the signed digest remains immutable. This is why the tampered digest failed verification while the original digest still passed verification.

The “subject digest” is the content-addressed manifest digest of the signed artifact. In practice, verification should always be performed against a digest reference, not just a tag, because the digest uniquely identifies the exact image contents.

---

## Task 2 — Attestations: SBOM and Provenance

### What I did
1. Generated a Syft-native SBOM for the signed image.
2. Converted the SBOM to CycloneDX JSON.
3. Attached the CycloneDX SBOM as an attestation.
4. Verified the SBOM attestation and decoded its payload.
5. Created a minimal provenance predicate.
6. Attached the provenance attestation.
7. Verified the provenance attestation and decoded its payload.

### Evidence
- Syft-native SBOM: `labs/lab4/syft/juice-shop-syft-native.json`
- CycloneDX SBOM: `labs/lab8/attest/juice-shop.cdx.json`
- Verified SBOM attestation: `labs/lab8/attest/verify-sbom-attestation.jsonl`
- Decoded SBOM payload: `labs/lab8/attest/sbom-payload.json`
- Pretty SBOM payload: `labs/lab8/attest/sbom-payload.pretty.json`
- Provenance predicate: `labs/lab8/attest/provenance.json`
- Verified provenance attestation: `labs/lab8/attest/verify-provenance.jsonl`
- Decoded provenance payload: `labs/lab8/attest/provenance-payload.json`
- Pretty provenance payload: `labs/lab8/attest/provenance-payload.pretty.json`

### Analysis
A signature answers the question: **“Was this artifact signed by the expected key?”**  
An attestation answers the question: **“What signed metadata claims are attached to this artifact?”**

The SBOM attestation contains software composition metadata for the image in CycloneDX format. From the decoded payload, the attestation subject is the same Juice Shop image digest, and the predicate is a CycloneDX BOM containing package/component metadata for the container contents.

The provenance attestation provides build-context information for supply chain security. In this lab it records:
- builder ID: `student@local`
- build type: `manual-local-demo`
- image parameter: the signed Juice Shop digest reference
- build start timestamp
- completeness flags for parameters/environment/materials

This strengthens supply chain security because consumers can verify both integrity and metadata claims bound to the same immutable subject digest.

---

## Task 3 — Artifact (Blob/Tarball) Signing

### What I did
1. Created `sample.txt`.
2. Packed it into `sample.tar.gz`.
3. Signed the tarball and produced a bundle file.

### Evidence
- Source file: `labs/lab8/artifacts/sample.txt`
- Tarball: `labs/lab8/artifacts/sample.tar.gz`
- Bundle: `labs/lab8/artifacts/sample.tar.gz.bundle`

### Result and analysis
The blob signing step produced the tarball bundle successfully, but the final verification step did not complete successfully in the current local setup. The reported error was:

> `failed to verify log inclusion: not enough verified log entries from transparency log: 0 < 1`

So, for the artifact-signing task, signing output was created, but the final blob verification still needs an additional local fix related to transparency log expectations in the current Cosign setup.

Blob signing is useful for release binaries, archives, model artifacts, scripts, or configuration bundles distributed outside a container registry. The difference from image signing is that blob signing targets a regular file directly, while image signing targets an OCI artifact in a registry and is normally verified against its digest reference.

---

## Windows-specific notes
The original lab commands were Linux-oriented, so the workflow was adapted for PowerShell. The main changes were:
- replacing shell-specific constructs with PowerShell equivalents,
- handling local registry digest resolution through PowerShell web requests,
- adapting Cosign invocation for the Windows executable name,
- working around newer Cosign behavior related to transparency log configuration in local signing flows.

---

## Deliverables checklist
- [x] Task 1 — Local registry, signing, verification (+ tamper demo)
- [x] Task 2 — Attestations (SBOM + provenance) + payload inspection
- [ ] Task 3 — Artifact signing fully verified

## Short conclusion
The lab successfully demonstrated local image signing and verification, tamper detection through digest-based verification, and attachment plus validation of SBOM and provenance attestations. The remaining issue is the final blob verification step for the tarball artifact, which failed because the current local Cosign configuration expected a verified transparency log entry for the blob bundle.
