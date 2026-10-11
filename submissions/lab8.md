# Lab 8 — Submission
## Task 1: Sign + Tamper Demo
### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d`
### Signing
- Output of `cosign sign` (success line):
Pushing signature to: localhost:5000/juice-shop

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"cosign container image signature"},"optional":{"Bundle":{"SignedEntryTimestamp":"MEYCIQDSJIhyvWHHFPtZSWbR/CRaoNlpVavwaJV28CNbztaOgQIhAKp6nelSUcZvFVcRywXq+k4pbEkcyQdXHGQdUSSfvy7c","Payload":{"body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2MzY5MDc0MzhmYTM3YzA3ZDA1ZDhiYmM5MzExMWFkNWY5MmY0ZmE1N2EyNDRjMGY3ODEwZTMxZTM0NzFhNGZmIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJQi9lVG53RzhmK29JalFkSko2QkY5RWNoWTRWRzcxblg2T0lIMzcyNnNkTUFpRUFqTEh3Q0YzWmpDTm43WmN5SldDSjE0TWpsSUpBTXRFT2djTUVpUHQ3TzdVPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGT1N0Q2JrTjBUR0ZWYjNsRFlWZHpkbEUxT0hscUszUmlUVmt3Y0Fwek4wbExZa05CTVdZclMzcFpZakFyVkN0UmIwVXdZbWxDUjJjeFFqazVZVTlyVDAwMVZqbHZkbVk1UmxOQk9GVm9hMlF6VFRScFJFMVJQVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=","integratedTime":1783109783,"logIndex":2063967325,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}}}}]

```
### Tamper Demo (FAILED — correctly)
Output of cosign verify on tampered digest:
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
main.go:69: error during command execution: no signatures found
```
### Sanity — original still verifies
```
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
Why digest binding matters (Lecture 8 slide 6)
Cosign binds the signature to the immutable image digest (SHA-256 of the image bytes), not to the human-readable tag. In the tamper demo, Alpine was re-tagged as juice-shop:v20.0.0-tampered, which produced a completely different digest (sha256:6c2a9711...) with no matching signature. If Cosign had signed only the tag :v20.0.0, an attacker could push malicious content under the same tag name and verification would still appear to pass — digest binding prevents this tag-mutation attack because the signature is cryptographically tied to the exact byte stream that was signed.
```

### Why digest binding matters (Lecture 8 slide 6)
Cosign binds the signature to the immutable image digest (SHA-256 of the image bytes), not to the human-readable tag. In the tamper demo, Alpine was re-tagged as juice-shop:v20.0.0-tampered, which produced a completely different digest (sha256:6c2a9711...) with no matching signature. If Cosign had signed only the tag :v20.0.0, an attacker could push malicious content under the same tag name and verification would still appear to pass — digest binding prevents this tag-mutation attack because the signature is cryptographically tied to the exact byte stream that was signed.


## Task 2: SBOM + Provenance Attestations
### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (first 30 lines of decoded payload):
```json
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"
      }
    }
  ],
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
- diff between Lab 4 SBOM and extracted-from-attestation SBOM: `` (empty diff = success)
### Provenance attestation
- Attached: yes
- Builder ID in predicate: https://localhost/lab8-student
- buildType in predicate: https://example.com/lab8/local-build
### What this gives a Lab 9 verifier (2-3 sentences)
A signed image alone only proves who built/published it — it does not tell you what is inside. A signed image with a CycloneDX SBOM attestation lets an admission controller (e.g. Kyverno verify-images) require both a trusted signature AND a verifiable component list at deploy time. When the next Log4Shell hits, the "signed but no SBOM" image forces manual forensics to find affected libraries; the "signed with SBOM" image lets you query the attestation immediately for log4j coordinates and block or quarantine deployments before pods start.


## Bonus: Blob Signing 
### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
Verified OK

### Tamper test failed (correctly)
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob. Error: invalid signature when validating ASN.1 encoded signature main.go:74: error during command execution: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)
```
Codecov's bash uploader was distributed via `curl | bash` without signature verification, allowing a compromised script to run on CI machines. If consumers had run `cosign verify-blob --key cosign.pub --bundle install.sh.bundle install.sh` before executing the script, the modified bytes would have failed verification (`invalid signature`) and the pipeline would have stopped instead of running malicious code. This is exactly the `cosign verify-blob` API from Lecture 8 slide 14 — signing release artifacts at build time and verifying before execution closes the `curl | bash` trust gap.
```
