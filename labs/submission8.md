# Lab 8 Submission — Software Supply Chain Security: Signing, Verification, and Attestations

**Target image:** `bkimminich/juice-shop:v19.0.0`  
**Environment:** macOS + Docker 28.5.2 on Apple Silicon (`darwin/arm64`, Docker server `linux/aarch64`)  
**Cosign version used:** `v3.0.5`

This report documents the steps I completed locally for Lab 8, the commands and artifacts I used, and the results I obtained for each task. All outputs were saved under `labs/lab8/`. 

## Task 1 — Local Registry, Signing, Verification, and Tamper Demonstration

### What I did

I first prepared the working directories for the lab:

```bash
mkdir -p labs/lab8/{registry,signing,attest,analysis,artifacts,bin}
```

Because `cosign` was not installed globally in this environment, I downloaded a local binary to `labs/lab8/bin/cosign` and used that binary for the rest of the lab.

I then pulled the target image:

```bash
docker pull bkimminich/juice-shop:v19.0.0
```

Next, I started a local OCI registry on `localhost:5000`, tagged the Juice Shop image for that registry, and pushed it:

```bash
docker run -d --restart=always -p 5000:5000 --name registry registry:3
docker tag bkimminich/juice-shop:v19.0.0 localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

After the push, I resolved the registry tag to a digest reference and saved it to `labs/lab8/analysis/ref.txt`.

The digest reference used for signing and verification was:

```text
localhost:5000/juice-shop@sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7
```

I generated a local Cosign key pair and stored it under `labs/lab8/signing/`:

```bash
cosign generate-key-pair --output-key-prefix labs/lab8/signing/cosign
```

The lab handout uses `--tlog-upload=false`, but with `cosign v3.0.5` that exact local flow was no longer accepted in the same way. To keep the workflow local and avoid Rekor/TSA upload, I created a minimal local signing configuration without Rekor/TSA services and used that configuration for signing:

```bash
cosign sign --yes \
  --allow-http-registry \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/local-signing-config.json \
  --key labs/lab8/signing/cosign.key \
  "$REF"
```

I then verified the image signature with the public key:

```bash
cosign verify \
  --allow-http-registry \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF"
```

### Result

The verification of the original digest succeeded. The verification output confirmed that:

- the Cosign claims were validated
- the signatures were verified against the specified public key
- the digest reference matched the signed image

The full log for this part is saved in:

- `labs/lab8/analysis/task1-signing.log`

### Tamper demonstration

To demonstrate tampering, I deliberately replaced the content behind the `localhost:5000/juice-shop:v19.0.0` tag with `busybox:latest`:

```bash
docker pull busybox:latest
docker tag busybox:latest localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

After that, I resolved the tag again and saved the new digest reference to `labs/lab8/analysis/ref-after-tamper.txt`.

The new digest reference after tag tampering was:

```text
localhost:5000/juice-shop@sha256:50a3a2fef78c92dee45a3a9b72af5bdcbff6476e685cef49d97f286b6ce6f14a
```

I then verified the tampered digest with the same public key. That verification failed with:

```text
Error: no signatures found
tamper_verify_exit_code=10
```

As a sanity check, I verified the original digest again, and that verification still succeeded.

The tamper evidence is saved in:

- `labs/lab8/analysis/task1-tamper.log`
- `labs/lab8/analysis/ref-after-tamper.txt`

### How signing protects against tag tampering

Image tags are mutable, but signatures are tied to a specific digest. In this lab, the tag `localhost:5000/juice-shop:v19.0.0` was repointed to a different image after I replaced it with `busybox`. The original signature still validated only for the original digest and did not validate for the new digest. This is exactly how digest-based signing protects against tag tampering: the trust is bound to the content hash, not to the tag name.

### What “subject digest” means

The subject digest is the immutable hash of the exact artifact that is being signed or attested. In this lab, the relevant subject digest was:

```text
sha256:872efcc03cc16e8c4e2377202117a218be83aa1d05eb22297b248a325b400bd7
```

If the content changes, the digest changes. That means the old signature or attestation no longer applies to the new artifact.

## Task 2 — Attestations: SBOM and Provenance

### What I did

For the SBOM part, I reused the Syft SBOM from Lab 4 and converted it into CycloneDX JSON format:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab4/syft":/in:ro \
  -v "$(pwd)/labs/lab8/attest":/out \
  anchore/syft:latest \
  convert /in/juice-shop-syft-native.json -o cyclonedx-json=/out/juice-shop.cdx.json
```

I then attached that SBOM as an attestation to the original signed image digest:

```bash
cosign attest --yes \
  --allow-http-registry \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/local-signing-config.json \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "$REF"
```

After attaching the SBOM attestation, I verified it:

```bash
cosign verify-attestation \
  --allow-http-registry \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type cyclonedx \
  "$REF"
```

For provenance, I created a local predicate file at `labs/lab8/attest/provenance.json` with a minimal build statement containing:

- the image digest reference in the invocation parameters
- a local builder identifier
- a local build type
- an RFC3339 UTC timestamp

I attached it as a provenance attestation:

```bash
cosign attest --yes \
  --allow-http-registry \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/local-signing-config.json \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/provenance.json \
  --type slsaprovenance \
  "$REF"
```

Then I verified the provenance attestation:

```bash
cosign verify-attestation \
  --allow-http-registry \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type slsaprovenance \
  "$REF"
```

To inspect the attestation envelope as required by the lab, I decoded the base64 payloads using `jq` and saved the decoded JSON payloads and shorter summaries:

- `labs/lab8/attest/sbom-payload-decoded.json`
- `labs/lab8/attest/provenance-payload-decoded.json`
- `labs/lab8/attest/sbom-payload-summary.json`
- `labs/lab8/attest/provenance-payload-summary.json`

### Result

The attestation workflow completed successfully for both:

- the CycloneDX SBOM attestation
- the provenance attestation

The main log is saved in:

- `labs/lab8/attest/task2-attestations.log`

The verification outputs are saved in:

- `labs/lab8/attest/verify-sbom-attestation.json`
- `labs/lab8/attest/verify-provenance.json`

### SBOM attestation inspection

From the decoded SBOM attestation payload, I confirmed that:

- `predicateType` was `https://cyclonedx.org/bom`
- the attestation subject pointed to `localhost:5000/juice-shop`
- the subject digest matched the original signed digest
- `bomFormat` was `CycloneDX`
- `specVersion` was `1.6`
- the payload recorded `3532` components

The summary also showed image metadata such as:

- container name `bkimminich/juice-shop`
- version `v19.0.0`
- image labels including title, vendor, source, documentation URL, and license
- Syft as the SBOM generation tool

### Provenance attestation inspection

From the decoded provenance attestation payload, I confirmed that:

- `predicateType` was `https://slsa.dev/provenance/v0.2`
- the subject digest matched the original signed digest
- `builder.id` was `student@local`
- `buildType` was `manual-local-demo`
- `buildStartedOn` was `2026-03-30T14:01:42Z`
- the completeness block recorded `parameters=true`

### How attestations differ from signatures

A signature proves that a specific artifact digest was signed by the holder of the signing key. An attestation also attaches signed metadata or claims about that artifact. In this lab:

- the image signature proved integrity for the digest
- the SBOM attestation added a signed inventory of image contents
- the provenance attestation added signed metadata about how the artifact was produced

### What information the SBOM attestation contains

The SBOM attestation contains the software bill of materials for the image. In this lab, that included:

- the subject image digest
- CycloneDX document metadata
- the image component metadata
- a large component inventory generated from the image
- metadata about the SBOM generation tool

This makes the attestation useful for verifying not only that the image was signed, but also what software content was present in that signed image.

### What provenance attestations provide for supply chain security

The provenance attestation provides evidence about how an artifact came to exist. Even in this simple local example, it recorded:

- who the builder was
- what kind of build process was used
- when the build started
- what image parameter was used

In supply chain security terms, this helps consumers reason not only about integrity, but also about origin and build context.

## Task 3 — Artifact (Blob/Tarball) Signing

### What I did

I created a small text file and packed it into a tarball:

```bash
echo "sample content $(date -u +%Y-%m-%dT%H:%M:%SZ)" > labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt
```

I signed the tarball with Cosign and asked Cosign to produce a verification bundle:

```bash
cosign sign-blob \
  --yes \
  --key labs/lab8/signing/cosign.key \
  --signing-config labs/lab8/signing/local-signing-config.json \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz
```

I then verified the blob signature with the public key and the generated bundle:

```bash
cosign verify-blob \
  --key labs/lab8/signing/cosign.pub \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  --insecure-ignore-tlog \
  labs/lab8/artifacts/sample.tar.gz
```

### Result

The blob verification succeeded with:

```text
Verified OK
```

The relevant files are saved in:

- `labs/lab8/artifacts/task3-blob-signing.log`
- `labs/lab8/artifacts/verify-blob.txt`
- `labs/lab8/artifacts/sample.tar.gz.bundle`

### Use cases for signing non-container artifacts

Signing non-container artifacts is useful for files such as:

- release archives
- compiled binaries
- configuration bundles
- policy files
- exported SBOM files

### How blob signing differs from container image signing

Container image signing stores signatures and attestations in an OCI registry alongside the image digest. Blob signing works directly on a regular file and verifies that file using a detached signature or bundle. The trust goal is similar, but the storage and distribution model is different.

## Final Notes

The lab objectives were completed locally:

- the image was pushed to a local registry
- a Cosign signature was created and verified
- a tamper case was demonstrated and explained
- SBOM and provenance attestations were attached and verified
- attestation payloads were inspected and decoded
- a non-container artifact was signed and verified

All supporting evidence is stored under `labs/lab8/`.
