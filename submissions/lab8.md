# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe

### Signing
- Output of `cosign sign`:
```
Signing artifact...
Pushing signature to: localhost:5000/juice-shop
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
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

### Why digest binding matters (Lecture 8 slide 6)
The tampered re-tag pointed to a DIFFERENT digest (of an alpine image); the signature was bound to the ORIGINAL juice-shop digest. If Cosign had signed the tag instead, an attacker could simply re-tag a malicious image with the same tag and the signature would still appear valid for that tag, failing to detect the image swap.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (first 30 lines of decoded payload):
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "...",
    "tools": [
      {
        "vendor": "anchore",
        "name": "syft",
        "version": "1.41.x"
      }
    ]
  },
  "components": [
    ...
  ]
}
```
- Component count matches Lab 4 source: yes (3069 components)
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: (empty diff)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
A verifier can now enforce that an image is not only signed by a trusted entity but also possesses a valid SBOM. When a vulnerability like Log4Shell hits, the verifier (via Kyverno/Policy Controller) can instantly identify affected images by querying the attached SBOM attestations without needing to re-scan the entire registry.

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
Verified OK
```

### Tamper test failed (correctly)
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)
Codecov's bash uploader was distributed via `curl | bash` without verification. If consumers had run `cosign verify-blob` against a signed bundle before executing the script, the modified malicious version would have failed verification, preventing the execution of the attacker's code.
