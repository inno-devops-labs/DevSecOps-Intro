# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d

### Signing
- Output of `cosign sign` (just the success line is fine):
```
Signing artifact... \ Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
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

Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]

```

### Why digest binding matters (Lecture 8 slide 6)
2-3 sentences. The tampered re-tag pointed to a DIFFERENT digest; your signature was bound to the
ORIGINAL digest. What would have broken if Cosign had signed the tag instead?

If cosign signed the tag, the tampered image would pass verification. Because, the tag would match despite the images being different. So the signature would be useless.


## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (first 30 lines of decoded payload):
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

- Component count matches Lab 4 source: yes
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `` (empty diff = success)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
Lecture 8 slide 12 + Lecture 9 slide 4 — at K8s admission time, a Kyverno verify-images policy
can require BOTH signatures AND specific attestation predicates. What's the operational difference
between a "signed but no SBOM" image and a "signed with SBOM" image when the next Log4Shell hits?:
Signed but no SBOM ensures that image has not been tampered with, and signed with SBOM does that too, but also tells what packages are inside. When the next Log4Shell hits, the vulnerable image will be blocked if "signed with SBOM".


