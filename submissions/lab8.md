# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5001` (port 5000 was occupied by macOS AirPlay Receiver, so the registry was published on 5001)
- Image pushed: `localhost:5001/juice-shop:v20.0.0`
- Image digest: `localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113`

### Signing
Output of `cosign sign`:
```
Pushing signature to: localhost:5001/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
Verification for localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demo (FAILED — correctly)
The tag `v20.0.0-tampered` was re-pointed to `alpine:3.20`
(digest `sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`).
Output of `cosign verify` on the tampered digest:
```
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies
```
Verification for localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

### Why digest binding matters (Lecture 8 slide 6)
The tampered re-tag pointed at a different digest (the alpine image), while the signature was
bound to the original juice-shop digest — so the tampered pull produced "no signatures found"
and the original still verified. Had Cosign signed the mutable `:v20.0.0` tag instead of the
`@sha256:...` digest, an attacker who re-pushes a malicious image under that same tag would
inherit a valid-looking signature reference, because the tag can be silently repointed to any
digest. Digest binding guarantees the signature covers immutable content, not a movable label.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` succeeded)
- Verify-attestation output (decoded payload, first lines):
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
    "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "bomFormat": "CycloneDX",
    "components": [
      {
        "bom-ref": "pkg:npm/1to2@1.0.0?package-id=3cea2309a653e6ed",
        "cpe": "cpe:2.3:a:nodejs:1to2:1.0.0:*:*:*:*:*:*:*",
        ...
      }
    ]
  }
}
```
- Component count matches Lab 4 source: **yes** — 3068 (attestation) == 3068 (lab4)
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: empty (component counts identical)

### Provenance attestation
- Attached: yes (`cosign attest --type slsaprovenance` succeeded; `verify-attestation` passed)
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier
A "signed but no SBOM" image proves who built it but says nothing about what's inside, so when
the next Log4Shell drops you must re-scan or rebuild every image just to learn whether the
vulnerable library is present. A "signed with SBOM" image lets a verifier query the attested
component list directly and answer "are we affected?" in seconds, without touching the running
workload. At admission time a Kyverno verify-images policy can require BOTH a valid signature
AND the CycloneDX attestation predicate, so images that ship without an inventory never deploy.

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
Verified OK
```

### Tamper test failed (correctly)
After appending bytes to the tarball:
```
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation
Codecov's bash uploader was distributed via `curl | bash` with no integrity check, so when an
attacker modified the script on the distribution server every consumer's CI executed the
malicious version blindly. If those consumers had run
`cosign verify-blob --key cosign.pub --bundle uploader.bundle uploader.sh` before piping it to
`bash`, the altered bytes would no longer match the signature bound to the original blob and
verification would fail — exactly as the tamper test above fails — stopping the poisoned script
from ever running.
