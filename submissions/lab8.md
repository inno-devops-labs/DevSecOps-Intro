# Lab 8 — Supply Chain Security: Cosign Signing and Attestations

## Task 1: Local Registry, Image Signing, and Tamper Demo

### Registry and image push

- Local registry: `lab8-registry` on `localhost:5000`
- Original image: `localhost:5000/juice-shop:v20.0.0`
- Signed immutable digest:

```text
localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```

### Signing

Cosign signed the image digest using a local key pair. The private key is excluded from version control; only `labs/lab8/keys/cosign.pub` is committed.

```text
Flag --new-bundle-format has been deprecated, this will be the only supported format in future versions
Signing artifact...
Pushing signature to: localhost:5000/juice-shop
```

### Verification — original image passed

```json

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper demonstration — verification failed correctly

An Alpine image was pushed under the same repository name but with a separate tag, producing a different digest:

```text
localhost:5000/juice-shop@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
```

Verification of this digest failed as expected:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity check — original digest still verifies

```json

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters

Cosign signed the immutable original digest, not the mutable image tag. The tampered image had a different digest, so its content did not match any signature and verification failed. If Cosign signed only a tag, an attacker could repoint that tag to malicious content while preserving the tag name, making the signature meaningless.

---

## Task 2: SBOM and Provenance Attestations

### CycloneDX SBOM attestation

- Attached with: `cosign attest --type cyclonedx`
- Source SBOM components: 3069
- Extracted attested SBOM components: 3069
- Component-count comparison: identical
- The diff between both component counts was empty.

First 30 lines of the decoded in-toto attestation:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "components": [
      {
        "author": "Benjamin Byholm <bbyholm@abo.fi> (https://github.com/kkoopa/), Mathias Küsel (https://github.com/mathiask88/)",
        "bom-ref": "pkg:npm/1to2@1.0.0?package-id=3cea2309a653e6ed",
        "cpe": "cpe:2.3:a:nodejs:1to2:1.0.0:*:*:*:*:*:*:*",
        "description": "NAN 1 -> 2 Migration Script",
        "externalReferences": [
          {
            "type": "distribution",
            "url": "git://github.com/nodejs/nan.git"
          }
        ],
        "licenses": [
          {
            "license": {
              "id": "MIT"
```

### Provenance attestation

- Attached with: `cosign attest --type slsaprovenance`
- Builder ID: `https://localhost/lab8-student`
- Build type: `https://github.com/innopolis/devsecops-intro/lab8/local-build`

Decoded provenance attestation:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "buildType": "https://github.com/innopolis/devsecops-intro/lab8/local-build",
    "builder": {
      "id": "https://localhost/lab8-student"
    },
    "invocation": {
      "configSource": {
        "digest": {
          "sha1": "793db4a3fedb0c88e41ba639a40de29e47070f20"
        },
        "uri": "https://github.com/Troshkins/DevSecOps-Intro.git"
      }
    }
  }
}
```

### Value for admission-time verification

At Kubernetes admission time, a Kyverno or Sigstore policy can require both a valid image signature and required attestation predicates. A signed image without an SBOM proves who signed it, but does not provide a structured inventory of its dependencies. A signed image with an SBOM allows teams to query deployed artifacts when a new vulnerability such as Log4Shell appears and rapidly identify affected images.

---

## Bonus: Blob Signing — Codecov 2021 Mitigation

### Original blob verification passed

Artifact: `my-tool.tar.gz`
Bundle: `my-tool.tar.gz.bundle`

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

### Tampered blob verification failed correctly

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation

Codecov distributed its Bash uploader through a `curl | bash` workflow without mandatory signature verification. Consumers could instead download the artifact and its Cosign bundle, then run `cosign verify-blob` before executing it. After an attacker modified the uploader, verification would fail with an invalid signature, preventing the altered script from being trusted or executed.
