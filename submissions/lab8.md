# Lab 8 — Submission

## Environment

- Docker: `27.5.1`
- Cosign: `v2.4.3`
- jq: `1.7.1`
- Branch: `feature/lab8`
- Source commit: `7f777bf2b97dee0362254be52e4d9aba16948893`

## Task 1: Sign + Tamper Demo

### Registry + image push

- Registry container: `lab8-registry` on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d`

```text
localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d
```

### Signing

The image was signed by immutable registry digest using the generated Cosign private key.

```text
Pushing signature to: localhost:5000/juice-shop
```

The private key is excluded from Git. The public key is committed as `labs/lab8/keys/cosign.pub`.

### Verification — passed

`cosign verify` validated both the Cosign claims and the signature against the public key:

```text
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

The verified claim binds the signature to the expected manifest digest:

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "localhost:5000/juice-shop"
      },
      "image": {
        "docker-manifest-digest": "sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"
      },
      "type": "cosign container image signature"
    },
    "optional": null
  }
]
```

### Tamper demo — failed correctly

Alpine `3.20` was pushed under a Juice Shop-looking tag. It resolved to a different digest:

```text
localhost:5000/juice-shop@sha256:6c2a9711b0a9f32b0239d9222eb1072309cf46c6431d319ae249186d811a987c
```

Verification returned exit code `10` and failed because no signature existed for the substituted digest:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies

The original digest was verified again after the tamper test:

```text
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

### Why digest binding matters

An OCI tag is a mutable reference and can be moved to a different manifest, while a digest is a content-addressed identifier for one exact manifest. The tampered tag resolved to `sha256:6c2a...`, but the signature covered only the original `sha256:8c76...` digest, so verification failed. If trust were attached only to the tag name, an attacker could retarget that tag to malicious content while preserving the apparently trusted image name.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

- Attached with `cosign attest --type cyclonedx`: **yes**
- Verification with `cosign verify-attestation --type cyclonedx`: **passed**
- CycloneDX version: `1.6`
- Source component count: `3069`
- Attested component count: `3069`
- Component-count diff: empty
- Full normalized SBOM diff: empty

Decoded attestation excerpt:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:389ef301-1899-4bd7-abc6-526cb7c33477",
    "version": 1,
    "components": [
      {
        "name": "1to2",
        "version": "1.0.0",
        "type": "library",
        "purl": "pkg:npm/1to2@1.0.0"
      }
    ]
  }
}
```

The complete decoded evidence is saved in `labs/lab8/results/sbom-attestation-report-excerpt.json`, and the count comparison is saved in `labs/lab8/results/sbom-component-counts.txt`.

### Provenance attestation

- Attached with `cosign attest --type slsaprovenance`: **yes**
- Verification with `cosign verify-attestation --type slsaprovenance`: **passed**
- Builder ID: `https://localhost/lab8-artemii-mashanov`
- Build type: `https://example.com/lab8/local-build`
- Source URI: `https://github.com/raaller/DevSecOps-Intro.git`
- Source revision: `7f777bf2b97dee0362254be52e4d9aba16948893`

Decoded provenance statement:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"
      }
    }
  ],
  "predicate": {
    "builder": {
      "id": "https://localhost/lab8-artemii-mashanov"
    },
    "buildType": "https://example.com/lab8/local-build",
    "invocation": {
      "configSource": {
        "uri": "https://github.com/raaller/DevSecOps-Intro.git",
        "digest": {
          "sha1": "7f777bf2b97dee0362254be52e4d9aba16948893"
        }
      }
    }
  }
}
```

### What this gives a Lab 9 verifier

A valid image signature proves that the admitted digest was signed by the expected key, but it does not reveal which libraries are present. A signed CycloneDX attestation gives an admission controller a verifiable predicate tied to the same image digest, allowing policy to require both authenticity and an SBOM. During a Log4Shell-style incident, the signed SBOM can be queried for the affected package and version; a signed image without an SBOM remains authentic but operationally opaque and requires rescanning before impact can be determined.

## Bonus: Blob Signing — Codecov 2021 Mitigation

### Sign + verify

The release artifact and its Cosign bundle were created as:

```text
labs/lab8/results/my-tool.tar.gz
labs/lab8/results/my-tool.tar.gz.bundle
```

Verification of the unchanged artifact succeeded:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Verified OK
```

### Tamper test — failed correctly

After appending a malicious payload to the archive, `cosign verify-blob` returned exit code `1`:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Error: invalid signature when validating ASN.1 encoded signature
error during command execution: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation

The Codecov uploader attack depended on consumers executing remotely distributed content without first authenticating its exact bytes. A consumer that downloaded the uploader and ran `cosign verify-blob --key cosign.pub --bundle <bundle> <artifact>` before execution would reject any attacker-modified payload because its bytes would no longer match the signed digest. The script would therefore stop before invoking the altered uploader.

