# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113`

### Signing
- `cosign sign --key labs/lab8/keys/cosign.key --allow-insecure-registry --yes "$DIGEST"` completed successfully for the local registry digest above.

### Verification (PASSED)
Output of `cosign verify` on the original digest:

```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

Saved verification output: `labs/lab8/results/verify-original.json`

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on the tampered digest:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

Saved verification output: `labs/lab8/results/verify-tampered.txt`

### Sanity — original still verifies
- The original `localhost:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113` continued to verify successfully after the tampered image failed verification.

### Why digest binding matters (Lecture 8 slide 6)
Cosign signatures are bound to the immutable image digest, not the mutable tag. Re-tagging `alpine:3.20` to look like Juice Shop produced a different digest, so the original signature no longer matched. If Cosign signed only the tag, an attacker could repoint the tag to malicious content without breaking verification.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes, with `cosign attest --type cyclonedx`
- Saved verification output: `labs/lab8/results/verify-attestation-cyclonedx.json`
- Extracted SBOM: `labs/lab8/results/sbom-from-attestation.json`

Decoded attestation summary:

```json
{
  "predicateType": "https://cyclonedx.org/bom",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": 3068
}
```

- Component count matches Lab 4 source: yes, `3068`
- Diff between Lab 4 SBOM and the extracted-from-attestation SBOM: empty output from
  `diff <(jq -S '.components | length' labs/lab4/juice-shop.cdx.json) <(jq -S '.components | length' labs/lab8/results/sbom-from-attestation.json)`

### Provenance attestation
- Attached: yes, with `cosign attest --type slsaprovenance`
- Saved verification output: `labs/lab8/results/provenance-verify.json`
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
A Lab 9 admission policy can require both a valid image signature and specific attestations before the workload is admitted. A signed image without an SBOM only proves origin and integrity, while a signed image with an SBOM also gives responders and policy engines an inventory of components to evaluate when a new vulnerable dependency such as Log4Shell is disclosed.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed artifact: `labs/lab8/results/my-tool.tar.gz`
- Bundle: `labs/lab8/results/my-tool.tar.gz.bundle`

Verify-blob success output:

```text
Verified OK
```

### Tamper test failed (correctly)

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)
The Codecov attacker modified a distributed upload script, so consumers fetched trusted-looking bytes that were no longer the original release artifact. If CI users had distributed the script with a Cosign bundle and run `cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz` before executing it, the tampered payload would have failed verification and the malicious script would not have been run.
