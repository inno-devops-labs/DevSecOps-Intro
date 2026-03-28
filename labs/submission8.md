# Lab 8 Submission - Software Supply Chain Security

## Scope

- Target image: `bkimminich/juice-shop:v19.0.0`
- Local registry used for the lab: `127.0.0.1:5001`
- Original signed subject digest: `sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7`
- Tampered digest after tag overwrite: `sha256:50a3a2fef78c92dee45a3a9b72af5bdcbff6476e685cef49d97f286b6ce6f14a`

## Task 1 - Local Registry, Signing, Verification, and Tamper Demo

### 1.1 Image push and digest reference

The image was pushed to a local plain-HTTP registry and then resolved by digest instead of by tag.

Evidence:

- Digest reference before tampering: [labs/lab8/analysis/ref.txt](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/analysis/ref.txt)
- Digest reference after tampering: [labs/lab8/analysis/ref-after-tamper.txt](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/analysis/ref-after-tamper.txt)

Resolved references:

- Original: `127.0.0.1:5001/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7`
- After tamper: `127.0.0.1:5001/juice-shop@sha256:50a3a2fef78c92dee45a3a9b72af5bdcbff6476e685cef49d97f286b6ce6f14a`

### 1.2 Signature verification evidence

Verification of the original digest succeeded with the Cosign public key.

Evidence:

- Original digest verification: [labs/lab8/analysis/verify-original.txt](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/analysis/verify-original.txt)

Key result from the verification output:

- Cosign validated the claims and verified the signatures against `labs/lab8/signing/cosign.pub`.
- The original digest currently has three signed artifacts associated with it:
  - `https://sigstore.dev/cosign/sign/v1`
  - `https://cyclonedx.org/bom`
  - `https://slsa.dev/provenance/v0.2`

### 1.3 Tamper demonstration and analysis

After overwriting the `juice-shop:v19.0.0` tag in the local registry with `busybox:latest`, the tag resolved to a different digest. Verification of that new digest failed.

Evidence:

- Tampered digest verification failure: [labs/lab8/analysis/verify-tampered.txt](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/analysis/verify-tampered.txt)

Observed result:

- `cosign verify` for the tampered digest returned `no signatures found`.

Why signing protects against tag tampering:

- A mutable tag such as `v19.0.0` can be repointed to different content.
- The Cosign signature is bound to the immutable manifest digest, not to the mutable tag string.
- Once the tag was moved from digest `872efcc0...` to digest `50a3a2fe...`, the original signature no longer matched the new content.
- This is exactly why verification should always be performed against a digest reference.

What “subject digest” means:

- The subject digest is the exact manifest digest of the artifact being signed or attested.
- It is the immutable identity of the image content.
- In this lab, the signed subject was `sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7`.

## Task 2 - Attestations, Verification, and Payload Inspection

### 2.1 SBOM generation and CycloneDX conversion

I regenerated a Syft-native SBOM and converted it to CycloneDX JSON for attestation.

Evidence:

- Syft native SBOM: [labs/lab4/syft/juice-shop-syft-native.json](/Users/marianikolashina/DevSecOps-Intro/labs/lab4/syft/juice-shop-syft-native.json)
- CycloneDX SBOM: [labs/lab8/attest/juice-shop.cdx.json](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/attest/juice-shop.cdx.json)

Artifact facts:

- Syft-native SBOM size: about `3.5 MB`
- CycloneDX SBOM size: about `2.1 MB`
- CycloneDX format: `CycloneDX 1.6`
- Component count in the attested SBOM payload: `3532`
- Metadata component:
  - Name: `bkimminich/juice-shop`
  - Type: `container`
  - Version: `v19.0.0`

### 2.2 SBOM attestation evidence

The CycloneDX SBOM was attached as an in-toto attestation and verified successfully.

Evidence:

- SBOM attestation verification output: [labs/lab8/attest/verify-sbom-attestation.txt](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/attest/verify-sbom-attestation.txt)

Payload inspection summary from `jq`:

- Statement type: `https://in-toto.io/Statement/v0.1`
- Predicate type: `https://cyclonedx.org/bom`
- Subject name: `127.0.0.1:5001/juice-shop`
- Subject digest: `sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7`
- SBOM payload describes the Juice Shop container and 3532 components

What information the SBOM attestation contains:

- The exact image digest the SBOM applies to
- The SBOM document type and schema version
- The container identity (`bkimminich/juice-shop:v19.0.0`)
- The package inventory discovered by Syft
- Tool metadata showing the SBOM generator (`syft 1.42.1`)

### 2.3 Provenance attestation evidence

I also created and verified a simple provenance attestation for the same image digest.

Evidence:

- Provenance predicate: [labs/lab8/attest/provenance.json](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/attest/provenance.json)
- Provenance attestation verification output: [labs/lab8/attest/verify-provenance.txt](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/attest/verify-provenance.txt)

Payload inspection summary from `jq`:

- Statement type: `https://in-toto.io/Statement/v0.1`
- Predicate type: `https://slsa.dev/provenance/v0.2`
- Subject digest: `sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7`
- Build type: `manual-local-demo`
- Builder ID: `student@local`
- Invocation parameter:
  - `image = 127.0.0.1:5001/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7`
- Build timestamp: `2026-03-28T17:38:59Z`

How attestations differ from signatures:

- A signature proves that a signer approved a specific artifact digest.
- An attestation also binds to a digest, but it carries structured claims about the artifact, such as its SBOM or its build provenance.
- In practice, signatures answer “was this artifact signed by the expected key?” while attestations answer “what do we know about this artifact and where did it come from?”

What provenance attestations provide for supply chain security:

- They record build context that can be evaluated by policy.
- They bind the claimed build metadata to a specific immutable artifact digest.
- They support traceability by recording builder identity, build type, invocation inputs, and timestamps.
- They make it harder to substitute an artifact without also breaking the verified provenance chain.

## Task 3 - Artifact (Blob/Tarball) Signing

### 3.1 Blob signing evidence

A non-container artifact was created, signed, bundled, and verified.

Evidence:

- Sample source file: [labs/lab8/artifacts/sample.txt](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/artifacts/sample.txt)
- Tarball artifact: [labs/lab8/artifacts/sample.tar.gz](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/artifacts/sample.tar.gz)
- Cosign bundle: [labs/lab8/artifacts/sample.tar.gz.bundle](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/artifacts/sample.tar.gz.bundle)
- Blob verification output: [labs/lab8/artifacts/verify-blob.txt](/Users/marianikolashina/DevSecOps-Intro/labs/lab8/artifacts/verify-blob.txt)

Artifact facts:

- Tarball SHA-256: `71d0683c9ce8a73df12ab363453f49997ddc6f3472ed16d5e19ff3d3fb9bcbff`
- Tarball contents: `sample.txt`
- Sample text content was created with the UTC timestamp embedded during the lab run

Verification result:

- `cosign verify-blob` returned `Verified OK`
- Because the blob was signed with `--tlog-upload=false`, verification required `--insecure-ignore-tlog`

Use cases for signing non-container artifacts:

- Release binaries
- Configuration bundles
- SBOM files
- Helm charts or deployment manifests
- Tarballs distributed outside an OCI registry

How blob signing differs from container image signing:

- Blob signing signs a file directly and can store verification material in a bundle file.
- Container signing signs an OCI artifact identified by registry reference and digest.
- Container signing naturally fits registry workflows and referrers, while blob signing is useful for standalone files distributed through other channels.

## Lab Notes

- Cosign v3 required `--use-signing-config=false` together with `--tlog-upload=false` for this local lab flow.
- The registry had to be exposed on `127.0.0.1:5001` because macOS `ControlCenter` was already listening on host port `5000`.
- The registry was plain HTTP, so the correct verification/signing flag was `--allow-http-registry`.
- The private signing key is intentionally ignored via `.gitignore` and should not be committed.

## Acceptance Criteria Check

- [x] `labs/submission8.md` includes analysis and evidence for Tasks 1-3
- [x] Image pushed to local registry; Cosign signature created and verified
- [x] Tamper scenario demonstrated and explained
- [x] At least one attestation attached and verified; payload inspected with `jq`
- [x] Artifact signing performed and verified
- [x] Outputs saved under `labs/lab8/`
