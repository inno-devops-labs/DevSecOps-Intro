# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d`

### Signing
- Output of `cosign sign` (just the success line is fine):
```text
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)

Output of `cosign verify` on original digest:

```json
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"cosign container image signature"},"optional":null}]
```

### Tamper Demo (FAILED — correctly)

Output of `cosign verify` on tampered digest:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
main.go:69: error during command execution: no signatures found
```

### Sanity — original still verifies

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"cosign container image signature"},"optional":null}]
```

### Why digest binding matters (Lecture 8 slide 6)

Cosign signs the immutable image digest rather than a mutable tag such as `v20.0.0`. In the tamper demonstration, the tag was redirected to a completely different digest, so the existing signature no longer matched and verification failed with `no signatures found`. If signatures were attached only to tags, an attacker could silently replace the image behind the same tag while verification would still appear valid.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

- Attached: yes (`cosign attest --type cyclonedx` exit 0)

- Verify-attestation output (first 30 lines of decoded payload):

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"
      }
    }
  ],
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "components": [
      {
        "type": "library",
        "name": "1to2",
        "version": "1.0.0"
      }
    ]
  }
}
```

- Component count matches Lab 4 source: **yes**
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `empty output (exit code 0)`

### Provenance attestation

- Attached: **yes**
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)

A normal image signature proves only that the image has not been modified and originated from the expected source. When a signed SBOM attestation is also available, admission policies can inspect the verified list of software components before the workload is deployed. During incidents such as Log4Shell, this allows Kubernetes policy engines to block images containing vulnerable packages without downloading and analyzing every container image.

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify

- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`

- Verify-blob success output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Error: invalid signature when validating ASN.1 encoded signature
main.go:74: error during command execution: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)

The Codecov attack succeeded because CI systems executed a downloaded Bash uploader script without verifying its authenticity. If users had first executed `cosign verify-blob --key codecov.pub --bundle uploader.sh.bundle uploader.sh`, any modification of the script would have invalidated the signature and stopped the pipeline before the malicious code could run. This adds cryptographic integrity checks to arbitrary files, not just container images.