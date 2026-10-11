# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push

- Registry container: `lab8-registry` running on `127.0.0.1:5000`
- Registry image used: `registry:2`
- Note: `registry:3` initially returned `403 Forbidden` for Cosign access over the local HTTP registry in my environment, so I used `registry:2` for the same local OCI signing workflow.
- Image pushed: `127.0.0.1:5000/juice-shop:v20.0.0`
- Image digest:

```text
127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

### Signing

Output of `cosign sign`:

```text
Pushing signature to: 127.0.0.1:5000/juice-shop
```

### Verification (PASSED)

Output of `cosign verify` on original digest:

```json
[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demo (FAILED — correctly)

The image `alpine:3.20` was re-tagged and pushed as `127.0.0.1:5000/juice-shop:v20.0.0-tampered`.

Tampered digest:

```text
127.0.0.1:5000/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
```

Output of `cosign verify` on tampered digest:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies

```json
[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters

Cosign signs the image digest, not just the mutable tag. In this lab, the tampered image used a similar-looking name, but it pointed to a different `sha256` digest, so the original signature did not match it. If Cosign signed only the tag, an attacker could replace what the tag points to and make a malicious image look trusted.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

- Attached: yes (`cosign attest --type cyclonedx` exited successfully)
- SBOM source: `labs/lab4/juice-shop.cdx.json`
- The SBOM was restored from the Lab 4 branch.
- Verify-attestation output was saved to `labs/lab8/results/sbom-attestation-verify.json`.
- Extracted SBOM was saved to `labs/lab8/results/sbom-from-attestation.json`.

Component count comparison:

```text
Lab 4 SBOM components:
3068
Attested SBOM components:
3068
```

Diff between Lab 4 SBOM and extracted SBOM component count:

```text

```

Empty diff means success.

### Provenance attestation

- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-gleb`
- buildType in predicate: `https://example.com/lab8/local-build`
- Verify-attestation output was saved to `labs/lab8/results/provenance-verify.json`.

Decoded provenance predicate:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "127.0.0.1:5000/juice-shop",
      "digest": {
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "buildType": "https://example.com/lab8/local-build",
    "builder": {
      "id": "https://localhost/lab8-gleb"
    },
    "invocation": {
      "configSource": {
        "digest": {
          "sha1": "abc123"
        },
        "uri": "https://github.com/darkdevinvader/DevSecOps-Intro"
      }
    }
  }
}
```

### What this gives a Lab 9 verifier

A signed image proves that the image digest was approved by the holder of the signing key. A signed image with an SBOM attestation gives the verifier more context: it can check not only who signed the image, but also what components are inside it. If a new Log4Shell-style vulnerability appears, admission policies or security tools can check the SBOM and block or flag affected images before deployment.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify

- Signed artifact: `my-tool.tar.gz`
- Signature bundle: `my-tool.tar.gz.bundle`

Verify-blob success output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed correctly

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation

The Codecov attack class was dangerous because users downloaded and executed a remote script without verifying that it was the original trusted file. If CI users had verified the script or archive with `cosign verify-blob` before running it, the modified attacker-controlled version would not have matched the original signature. In this lab, the tampered tarball failed verification for the same reason: the signature was bound to the exact original bytes.
