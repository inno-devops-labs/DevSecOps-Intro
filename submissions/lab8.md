# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`


### Signing
- Output of `cosign sign` (just the success line is fine):
```
tlog entry created with index: 2039164774
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"cosign container image signature"},"optional":{"Bundle":{"SignedEntryTimestamp":"MEQCIAgRzokPiWhbjvX2Iyu3SUDSO9uCRSPNoxedBC+izPrwAiABR7QVdlerjwOJjbXg8R6kYjLpMZ10l/aMXx78dxv06Q==","Payload":{"body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI3OTgwNzhjNTlhMGYxNjdiYWFhYTc4ZjkwM2E3MWIwZGI5NThhMTk3ZWU1ZGZiOWIzNTA0ZTQ2MzAwNWQ0MTlhIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUR0ME5VcVJxQW9aYmlZVU5vRkVSeXNRdmg0YVIyQzdER0R6Ri9oaDJMSHZnSWhBSlhMczJGV3hqRDZ5VWxMdUVVa1lyd21zOENpeWtSS3VnQWcwb1M4Q1NIQyIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGVjFSV1FVUkVUV0pJTVVWTlYzTTViWEZ6TjNwVGJtcG9SRkZpT0FwQ1ltUTBWM1Z5YlVwa04wSTFhMHBUTUhCMFoxTm1ZM1pYTUdsdE5raFdOMFkxWldSSk5rUm5OblppV2pGVWMydGxkSFp4UVhoVGRXNTNQVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=","integratedTime":1782927076,"logIndex":2039164774,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}}}}]
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
Error: no signatures found
main.go:69: error during command execution: no signatures found
```

### Sanity — original still verifies
```
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

### Why digest binding matters (Lecture 8 slide 6)
Cosign signs the digest (@sha256:...), not the tag (:v20.0.0). Tags are mutable so an attacker could push a malicious image under the same tag. If Cosign had signed the tag, the signature would still pass verification after the malicious push. Signing the digest ensures that the signature is bound to the exact image content, making tag substitution detectable.


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
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
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
            }
          }
        ],
        "name": "1to2",
        "properties": [
          {
            "name": "syft:package:foundBy",
            "value": "javascript-package-cataloger"
          },
          {
            "name": "syft:package:language",
            "value": "javascript"
          },
          {
            "name": "syft:package:type",
            "value": "npm"
          }
        ],
        "type": "library",
        "version": "1.0.0"
      }
    ]
  }
}
```
- Component count matches Lab 4 source: yes
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: ` ` (empty diff = success)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://github.com/ironveils/DevSecOps-Intro`
- buildType in predicate: `https://github.com/ironveils/DevSecOps-Intro/lab8`

### What this gives a Lab 9 verifier
At K8s admission time, a verifier can require both signature AND SBOM attestation. A "signed but no SBOM" image proves who built it, but doesn't help with incident response. A "signed with SBOM" image provides a machine-readable inventory of all components: when the next Log4Shell drops, the team can instantly query which images contain the vulnerable library without re-scanning or re-pulling the image.


## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)
```
Error: invalid signature when validating ASN.1 encoded signature
main.go:74: error during command execution: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation
Codecov's bash uploader was distributed via `curl | bash` without signature verification. If consumers had been running `cosign verify-blob` before piping to bash, the attacker's modified script would have failed verification because its digest would not match the signed one. The attack would have been detected before execution.