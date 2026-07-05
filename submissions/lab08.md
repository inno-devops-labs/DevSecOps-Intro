# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: <localhost:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113>

### Signing
- Output of `cosign sign` (just the success line is fine):
```
<Enter password for private key:
Pushing signature to: localhost:5000/juice-shop>
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
<paste labs/lab8/results/verify-original.json>
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
<paste labs/lab8/results/verify-tampered.txt — must contain "no matching signatures">
```

### Sanity — original still verifies
```
<Verification for localhost:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:cbdfc00de..."},"image":{"docker-manifest-digest":"sha256:cbdfc00de..."},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]>
```

### Why digest binding matters (Lecture 8 slide 6)
2-3 sentences. The tampered re-tag pointed to a DIFFERENT digest; your signature was bound to the
ORIGINAL digest. What would have broken if Cosign had signed the tag instead?
Slide 6 states the rule directly: "Cosign signs the digest of the image (@sha256:...), not the tag. Tags are mutable; digests aren't". The tamper demo showed this in practice — pushing alpine as `localhost:5000/juice-shop:v20.0.0-tampered` created a new digest (`45e09956dc...`), and `cosign verify` correctly failed with `no signatures found` because no signature exists for that new digest, while the original digest (`cbdfc00de...`) still verified. Had Cosign signed the tag `:v20.0.0` instead, an attacker who could re-point that tag at a malicious image would inherit the signature by definition — the tag is mutable, so anything under it becomes "signed" from the verifier's point of view. Digest binding removes this attack surface entirely: the signature is a claim about specific bytes, and mutating the tag cannot change which bytes exist under the old hash.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (first 30 lines of decoded payload):
```json
<Отлично, diff пустой + exit 0 = SBOM'ы идентичны по components.length ✅
Готовая замена секции Task 2. Замени раздел ## Task 2: SBOM + Provenance Attestations на этот блок:
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
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
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
              "id": "MIT">
```
- Component count matches Lab 4 source: yes
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `<exit: 0>` (empty diff = success)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `<https://localhost/lab8-student>`
- buildType in predicate: `<https://example.com/lab8/local-build>`

### What this gives a Lab 9 verifier (2-3 sentences)
Lecture 8 slide 12 + Lecture 9 slide 4 — at K8s admission time, a Kyverno verify-images policy
can require BOTH signatures AND specific attestation predicates. What's the operational difference
between a "signed but no SBOM" image and a "signed with SBOM" image when the next Log4Shell hits?
Slide 12 of Lecture 8 opens with "A signature you don't verify is decoration" and shows a Kyverno `verifyImages` ClusterPolicy that requires `attestors[].entries[].keys.publicKeys` — the admission-time hook that will consume the signatures we produced in this lab. Slide 4 of Lecture 9 places the same idea in a bigger picture: at the Deploy stage, the course-standard checks are "Policy-as-code, supply-chain verify" via Conftest and `cosign verify`, and the failure class this stage explicitly cannot catch is "a compromised registry serving a different image" — which is exactly what our tamper demo simulated in Task 1. The operational difference at the next Log4Shell moment: a "signed but no SBOM" image lets the admission controller confirm only "these bytes came from a trusted key", so the ops team must `docker pull` every image and re-scan to answer "are we affected?"; a "signed with SBOM" image lets the same policy additionally require the cyclonedx attestation predicate we attached here, and the ops team queries the attested SBOMs directly — the answer is authoritative because the SBOM is signed by the same key that signed the image.
## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
<WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK>
```

### Tamper test failed (correctly)
```
<WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature>
```

### Codecov 2021 mitigation (2-3 sentences)
Codecov's bash uploader was distributed via `curl | bash` without signature verification.
If their CI consumers had been running `cosign verify-blob` before `bash`-ing the script,
how would the attack have failed? Reference Lecture 8 slide 14 + the specific cosign command
that would have caught it.
Codecov's bash uploader was distributed via `curl -s https://codecov.io/bash | bash` with no signature check between download and execution. If consumers had been running `cosign verify-blob --key codecov.pub --bundle uploader.sh.bundle uploader.sh` between the `curl` and the `bash`, the modified uploader would have failed with the same `invalid signature` error demonstrated above — the attacker's added bytes hash to a different value than the signed bundle covers. Slide 14 of Lecture 8 (Filippo Valsorda) frames this exactly right: "xz-utils proved that supply chain security is not a tool you buy. It's a discipline you maintain" — `cosign verify-blob` is the specific discipline step that would have turned Codecov's `curl | bash` from "trust the CDN" into "trust the key + the CDN".