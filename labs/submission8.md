# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Local Registry, Signing & Verification

### Local registry setup

I started a local Docker registry for the lab. Host port `5000` was already occupied on my machine by system process, so I mapped the registry container port `5000` to host port `5500`.

Evidence:

* `labs/lab8/registry/registry-start.txt`
* `labs/lab8/registry/docker-ps.txt`

### Pull, tag, and push

I pulled the target image `bkimminich/juice-shop:v19.0.0`, tagged it for the local registry, and pushed it to `localhost:5500`.

Evidence:

* `labs/lab8/registry/docker-pull.txt`
* `labs/lab8/registry/docker-push.txt`

During push, Docker reported that only the available single-platform image was pushed to the local registry. Because of that, the local registry digest differed from the upstream digest.

Original signed digest:

```text
sha256:772d...ff3a5
```

Evidence:

* `labs/lab8/analysis/digest-original.txt`
* `labs/lab8/analysis/ref.txt`

### Image signing and verification

I generated a local Cosign key pair and signed the image in the local registry by digest. Verification with the public key succeeded.

Evidence:

* `labs/lab8/signing/key-files.txt`
* `labs/lab8/signing/sign-image.txt`
* `labs/lab8/signing/verify-image.txt`

### Tamper demonstration

To demonstrate tag tampering, I replaced the content behind the mutable tag `localhost:5500/juice-shop:v19.0.0` with `busybox:latest` and pushed it to the same tag.

Then I resolved the tag again to a new digest and attempted verification. Verification failed with:

```text
Error: no signatures found
```

However, verification of the original digest still succeeded.

Evidence:

* `labs/lab8/registry/docker-pull-busybox.txt`
* `labs/lab8/registry/docker-push-tampered.txt`
* `labs/lab8/analysis/digest-after-tamper.txt`
* `labs/lab8/analysis/ref-after-tamper.txt`
* `labs/lab8/signing/verify-tampered.txt`
* `labs/lab8/signing/verify-original-after-tamper.txt`

### Analysis

Signing protects against tag tampering because Cosign signs the immutable image digest, not just the mutable tag. A tag such as `v19.0.0` can be reassigned to different content later, but the digest uniquely identifies a specific manifest. If the tag is changed to point to another image, the digest also changes, so verification for that new digest fails.

The “subject digest” is the exact immutable cryptographic digest of the artifact that was signed. It identifies the specific image manifest content and is the object that the signature binds to.

---

## Task 2 — Attestations: SBOM and Provenance

### SBOM attestation

I reused the Syft-native SBOM from Lab 4 and converted it to CycloneDX JSON format. Then I attached it to the signed image as a Cosign attestation.

Evidence:

* `labs/lab8/attest/syft-convert.txt`
* `labs/lab8/attest/juice-shop.cdx.json`
* `labs/lab8/attest/attest-sbom.txt`
* `labs/lab8/attest/verify-sbom-attestation.txt`

### SBOM payload inspection

I extracted the attestation payload from the verified attestation output, decoded the base64 payload, and inspected it with `jq`.

The decoded SBOM attestation showed:

* in-toto statement wrapper
* `predicateType` corresponding to CycloneDX SBOM
* the attested subject image and digest
* a large list of software components in the SBOM

Evidence:

* `labs/lab8/attest/verify-sbom-attestation.json`
* `labs/lab8/attest/verify-sbom-attestation.pretty.json`
* `labs/lab8/attest/sbom-payload-decoded.json`
* `labs/lab8/attest/sbom-payload-inspection.txt`
* `labs/lab8/attest/sbom-predicate-type.txt`
* `labs/lab8/attest/sbom-subject.txt`
* `labs/lab8/attest/sbom-components-sample.txt`
* `labs/lab8/attest/sbom-components-count.txt`

### Provenance attestation

I created a minimal provenance predicate locally and attached it as a Cosign attestation of type `slsaprovenance`.

The decoded provenance payload showed:

* `predicateType: https://slsa.dev/provenance/v0.2`
* subject image: `localhost:5500/juice-shop`
* subject digest: `sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5`
* builder id: `student@local`
* build type: `manual-local-demo`
* invocation parameter referencing the exact image digest
* build metadata including `buildStartedOn`

Evidence:

* `labs/lab8/attest/provenance.json`
* `labs/lab8/attest/provenance-created.txt`
* `labs/lab8/attest/attest-provenance.txt`
* `labs/lab8/attest/verify-provenance.txt`
* `labs/lab8/attest/verify-provenance.json`
* `labs/lab8/attest/verify-provenance.pretty.json`
* `labs/lab8/attest/provenance-payload-decoded.json`
* `labs/lab8/attest/provenance-payload-inspection.txt`
* `labs/lab8/attest/provenance-predicate-type.txt`
* `labs/lab8/attest/provenance-subject.txt`
* `labs/lab8/attest/provenance-predicate.txt`

### Analysis

A signature proves that a specific artifact digest was signed by the holder of a private key. An attestation is different: it is signed metadata about the artifact. A signature answers “was this artifact signed by the expected identity/key?”, while an attestation answers “what information is being asserted about this artifact?”

The SBOM attestation contains software inventory information such as discovered packages/components, versions, metadata, and references. This supports dependency visibility, license review, vulnerability matching, and incident response.

The provenance attestation provides build-context information. In this lab it includes the builder identity, build type, invocation parameters, and build timestamp. In a real CI/CD supply chain, provenance helps establish where and how an artifact was produced and improves traceability and trust.

---

## Task 3 — Artifact (Blob/Tarball) Signing

I created a sample text file, archived it into a tarball, signed it with `cosign sign-blob`, and verified it with `cosign verify-blob`.

Evidence:

* `labs/lab8/artifacts/sample.txt`
* `labs/lab8/artifacts/sample.tar.gz`
* `labs/lab8/artifacts/sample.tar.gz.bundle`
* `labs/lab8/artifacts/artifact-files.txt`
* `labs/lab8/artifacts/sign-blob.txt`
* `labs/lab8/artifacts/verify-blob.txt`

### Analysis

Signing non-container artifacts is useful for release archives, binaries, configuration bundles, scripts, policy files, and other deliverables distributed outside container registries.

Blob signing differs from container image signing because a blob is signed as a standalone file, while a container image signature is associated with an OCI image digest stored in a registry. Container signing focuses on registry-hosted image manifests and digests, while blob signing protects the exact bytes of a local file.

Blob verification initially failed with the error:

```text
signature not found in transparency log
```

This occurred because the blob was signed with --tlog-upload=false, meaning the signature was not recorded in the transparency log (Rekor).

Verification succeeded after using the --insecure-ignore-tlog flag, which disables transparency log verification. This is acceptable in this local lab setup but would be insecure in production, as it removes auditability and transparency guarantees.

---

## Final notes

This lab demonstrated:

* local registry usage for signing experiments;
* image signing and verification with Cosign;
* protection against tag tampering by verifying immutable digests;
* SBOM and provenance attestations with payload inspection;
* signing and verifying a non-container artifact.

All evidence and logs are stored under `labs/lab8/`.
