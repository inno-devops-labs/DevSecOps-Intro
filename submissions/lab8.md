# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5001`
- Image pushed: `localhost:5001/juice-shop:v20.0.0`
- Image digest: `localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113`


### Signing
- Output of `cosign sign`: `Pushing signature to: localhost:5001/juice-shop`


### Verification (PASSED)
Output of `cosign verify` on original digest:

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "image": {
        "docker-manifest-digest": "sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "type": "https://sigstore.dev/cosign/sign/v1"
    },
    "optional": {}
  }
]
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
Error: no signatures found
error during command execution: no signatures found
```
### Sanity — original still verifies
```
Verification for localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The signatures were verified against the specified public key
```

### Why digest binding matters (Lecture 8 slide 6)
Cosign signs immutable image digests, not tags. This ensures that even if a tag is reused or redirected to a different image (as in the tampered Alpine case), verification will fail because the cryptographic digest no longer matches the signed artifact. If tags were signed instead of digests, attackers could retag malicious images under trusted names without breaking verification, fully bypassing supply chain integrity guarantees.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (first 30 lines of decoded payload):
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "localhost:5001/juice-shop",
      "digest": {
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX"
  }
}
```
- Component count matches Lab 4 source: yes
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: no differences observed (identical structure)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `cosign.sigstore.dev/cosign/sign/v1`
- buildType in predicate: `https://cosign.sigstore.dev/attestation/v1`

### What this gives a Lab 9 verifier (2-3 sentences)
In Kubernetes admission control, a policy engine like Kyverno can enforce both image signatures and SBOM attestations tied to immutable digests. This ensures not only that an image is trusted, but also that its dependency graph is known and verified. In a real vulnerability scenario (e.g., Log4Shell), this allows blocking workloads that lack a verifiable SBOM, even if they are properly signed.