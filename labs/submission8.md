# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Environment

- OS: Windows + PowerShell
- Docker: Docker Desktop
- Local registry: localhost:5000
- Target image: bkimminich/juice-shop:v19.0.0
- Signing tool: Cosign v3.0.6
- JSON inspection tool: jq 1.8.1
- Builder identity in provenance: v.galkin@innopolis.university

## Task 1 — Local Registry, Signing, Verification, and Tamper Demo

For Task 1, I pulled the target Juice Shop image, pushed it to a local Docker registry, resolved the local image by digest, generated a Cosign key pair, signed the image digest, and verified the signature with the public key.

The signed image reference was:

    localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58

Evidence files:

- labs/lab8/analysis/ref.txt
- labs/lab8/analysis/verify-original.txt

### Tamper demonstration

To demonstrate tag tampering, I replaced the local registry tag localhost:5000/juice-shop:v19.0.0 with busybox:latest and pushed it to the same tag.

The tampered image reference was:

    localhost:5000/juice-shop@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65

Verification of the tampered digest failed with "no signatures found", which is expected because the BusyBox digest was not signed with my Cosign key.

Evidence files:

- labs/lab8/analysis/ref-after-tamper.txt
- labs/lab8/analysis/verify-after-tamper-expected-fail.txt

I also verified the original signed digest again after the tamper demonstration. The original digest still verified successfully.

Evidence file:

- labs/lab8/analysis/verify-original-after-tamper.txt

### Analysis: tag tampering and subject digest

A Docker tag such as v19.0.0 is mutable. It can be changed to point to another image without changing the tag name. A digest such as sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58 is immutable and identifies the exact image manifest.

Cosign signs the subject digest, not only the human-readable tag. This means that if an attacker changes the tag to point to another image, the new digest will not have a valid signature from the trusted key. In this lab, after the tag was replaced with BusyBox, verification failed for the new digest but still succeeded for the original Juice Shop digest.

## Task 2 — Attestations: SBOM and Provenance

For Task 2, I generated a Syft SBOM for the Juice Shop image, converted it to CycloneDX JSON, attached it as a Cosign attestation, verified the attestation, and decoded the attestation payload.

Evidence files:

- labs/lab4/syft/juice-shop-syft-native.json
- labs/lab8/attest/juice-shop.cdx.json
- labs/lab8/attest/verify-sbom-attestation.json
- labs/lab8/attest/verify-sbom-attestation.stderr.txt
- labs/lab8/attest/sbom-payload-decoded.json
- labs/lab8/attest/sbom-payload-pretty.json

The decoded SBOM attestation payload contains an in-toto statement. Its subject is the signed Juice Shop image digest, and its predicate type is CycloneDX. The predicate contains software component and dependency information for the container image.

I also created a simple SLSA provenance predicate and attached it as a provenance attestation. The builder identifier is my university email address so that the local manual build is attributable during lab review.

Evidence files:

- labs/lab8/attest/provenance.json
- labs/lab8/attest/verify-provenance.json
- labs/lab8/attest/verify-provenance.stderr.txt
- labs/lab8/attest/provenance-payload-decoded.json
- labs/lab8/attest/provenance-payload-pretty.json

### Analysis: signature vs attestation

A signature proves that a specific artifact digest was signed by the holder of the private key and that the artifact has not been changed since signing.

An attestation is a signed statement about an artifact. It is also bound to the artifact digest, but it carries additional metadata. In this lab, the SBOM attestation describes the software components inside the image, while the provenance attestation describes how the artifact was produced.

### What the SBOM attestation provides

The SBOM attestation provides visibility into the dependencies and software packages inside the container image. This is useful for vulnerability management, dependency tracking, license review, and supply chain auditing.

### What the provenance attestation provides

The provenance attestation provides information about the build process and the builder identity. In this lab, it includes the build type, builder identifier, image reference, build timestamp, and parameter completeness. In a real supply chain security process, provenance helps determine whether an artifact came from an expected build process and whether it can be trusted.

## Task 3 — Artifact / Blob Signing

For Task 3, I created a sample non-container artifact as a tarball, signed it with Cosign sign-blob, and verified the blob signature using the public key and generated bundle.

Evidence files:

- labs/lab8/artifacts/sample.txt
- labs/lab8/artifacts/sample.tar.gz
- labs/lab8/artifacts/sample.tar.gz.bundle
- labs/lab8/artifacts/verify-blob.txt
- labs/lab8/artifacts/verify-blob-full.txt

### Use cases for signing non-container artifacts

Blob signing can be used for release binaries, scripts, configuration files, archives, deployment packages, Helm charts, and other files that are not container images.

### Difference between blob signing and container image signing

Container image signing is tied to an OCI image digest and stores signature-related data in the registry. Blob signing signs a normal file directly and uses an external signature or bundle file to verify that the file has not been modified.

## Conclusion

This lab demonstrated the main supply chain security workflow:

- signing and verifying a container image by digest;
- showing that tag tampering is detected because the new digest is not signed;
- attaching and verifying SBOM and provenance attestations;
- inspecting attestation payloads;
- signing and verifying a non-container artifact.

All evidence files are stored under labs/lab8/ and labs/lab4/syft/.
