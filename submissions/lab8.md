# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`

### Signing
- Output of `cosign sign` (just the success line is fine):
```
Signing artifact...
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies
```
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters (Lecture 8 slide 6)
The tampered re-tag pointed `localhost:5000/juice-shop:v20.0.0-tampered` at a different manifest digest (`sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e`), while the signature was bound to the original Juice Shop digest (`sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`). If Cosign signed only the mutable tag, an attacker could replace the tag target and still appear trusted. Digest-bound signatures prevent that because verification checks the exact immutable content digest.

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
        "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      }
    }
  ],
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components_count": 3069,
    "first_component": "1to2"
  }
}
```
- Component count matches Lab 4 source: yes (`3069`)
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: empty output

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

Decoded provenance predicate:
```json
{
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "buildType": "https://example.com/lab8/local-build",
    "builder": {
      "id": "https://localhost/lab8-student"
    },
    "invocation": {
      "configSource": {
        "digest": {
          "sha1": "480f4a445e0af8c10495aed968524a23aa1ea6b1"
        },
        "uri": "https://github.com/AskoRBINKAs/DevSecOps-Intro"
      }
    }
  }
}
```

### What this gives a Lab 9 verifier (2-3 sentences)
A Kyverno `verifyImages` admission policy can require the image signature and also require attestations such as a CycloneDX SBOM or SLSA provenance predicate. A signed image without an SBOM only proves who signed that exact digest; it does not give admission or response tooling a package inventory to query. A signed image with an SBOM lets the platform prove both integrity and inspectability, so when a new Log4Shell-style vulnerability appears, the verifier or scanner can map the deployed digest back to its declared components.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)
Codecov's bash uploader attack worked because CI jobs downloaded and executed a mutable script without verifying its bytes first. If consumers had required `cosign verify-blob --key cosign.pub --bundle codecov-uploader.bundle codecov-uploader` before running it, the modified uploader would not have matched the original signature bundle and verification would have failed. That blocks the `curl | bash` class of supply-chain attack before the malicious script gets execution inside CI.
