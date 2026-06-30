# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5001`
- Image pushed: `localhost:5001/juice-shop:v20.0.0`
- Image digest: localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113

### Signing
- Output of `cosign sign` (just the success line is fine):
```
Pushing signature to: localhost:5001/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[{"critical":{"identity":{"docker-reference":"localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
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
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.

Verification for localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

### Why digest binding matters (Lecture 8 slide 6)
Digest binding guarantees that we are signing the exact immutable bits of an image rather than a mutable tag pointer. If Cosign had signed the tag, an attacker could push a malicious image to the same tag (like `v20.0.0`), and naive verification tools would trust the compromised image because the tag name itself would have a valid signature attached to it, leading to a supply-chain compromise.

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
      "name": "localhost:5001/juice-shop",
      "digest": {
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      }
    }
  ],
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:155e81f1-3958-45e0-b615-1a8dbb5df200",
    "version": 1,
    "metadata": {
      "timestamp": "2026-06-28T14:33:00Z",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "aquasecurity",
            "name": "trivy",
            "version": "0.50.1"
          }
        ]
      }
    }
  }
}
```
- Component count matches Lab 4 source: yes
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: (empty diff = success)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
Having both signatures and attestations allows a Kubernetes admission controller (such as Kyverno) to verify not only who built the image, but also its contents (SBOM). When a new vulnerability (like Log4Shell) emerges, an attested image guarantees that the embedded SBOM is genuine and has not been tampered with. This enables security teams to instantly query running applications for vulnerable components without blindly trusting unverified specifications from third-party vendors.

---

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
The Codecov compromise occurred because clients were downloading a bash script and executing it directly (`curl | bash`) without any cryptographic integrity checks. If CI pipelines had required downloading both the script and its signature bundle, and then ran `cosign verify-blob` before execution, the hacker-modified script would have instantly failed verification (invalid signature). This would have completely prevented the supply chain attack from impacting hundreds of companies.
