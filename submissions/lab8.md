# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d`

### Signing
- Output of `cosign sign` (just the success line is fine):
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]

### Why digest binding matters (Lecture 8 slide 6)
Cosign's signature is bound to the image digest (a hash of the actual content), not to the tag (a mutable name). When I re-tagged a different image (alpine) as `v20.0.0-tampered`, it produced a completely different digest, so verification correctly failed with "no signatures found." Had Cosign signed the tag instead of the digest, an attacker could push a malicious image under the same tag and verification would still succeed, since the tag name stays the same even though the underlying content changed.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (component count check):3069
- Component count matches Lab 4 source: yes
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: (empty diff = success)

### Decoded predicate:
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
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "buildType": "https://example.com/lab8/local-build",
    "builder": {
      "id": "https://localhost/lab8-student"
    },
    "invocation": {
      "configSource": {
        "digest": {
          "sha1": "abc123"
        },
        "uri": "https://github.com/student/repo"
      }
    }
  }
}

## What this gives a Lab 9 verifier
An image that carries a signature, an SBOM attestation, and a provenance attestation gives a verifier (e.g. Kyverno at K8s admission time) three independent guarantees: (1) the image content has not been tampered with, (2) the exact list of components and versions it was built from, and (3) where and how it was built. When the next Log4Shell drops, a "signed with SBOM" image can be checked for the vulnerable component by name/version in seconds without a fresh scan, while a "signed but no SBOM" image would need to be rescanned from scratch or pulled from production until its contents are known.
