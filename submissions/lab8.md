# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push

- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Signing

- Output of `cosign sign` (just the success line is fine):

```
tlog entry created with index: 2063595522
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)

Output of `cosign verify` on original digest:

```json
[
  {
    "critical": {
      "identity": { "docker-reference": "localhost:5000/juice-shop" },
      "image": {
        "docker-manifest-digest": "sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      },
      "type": "cosign container image signature"
    },
    "optional": {
      "Bundle": {
        "SignedEntryTimestamp": "MEUCIQCHsMKdfib7PzlIP4lw7uXmax9cDJ8yBBu6FzD7GXKY7gIgLsW4j/N5hj7G0CgBbSRecOvrSqQL7ijdD0fdQxIP9rw=",
        "Payload": {
          "body": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIzNzQ2NjcyMGE3MTU2NjdkNTllMGExM2YwMDg2NTI0YzViYjFjYzgxMTIwMDIzNzk1N2RjNWI1Yzg1Njk3MDY5In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJRUszQmV5WmlOWWs4bFBjRTEyVUd3SnNzaDBsMmlnMkQ0VFhUSC9ZWkV1aUFpRUFubjZDTXgwN2RjNmFsNm8vb2VqOG1tY0xlVDU3bnJUOFJ5VzlTZmE0STNZPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGTm5jNFVuWmtXR2hsZUZVeVVrMDNNME0wWjI5SGJ5OVNSa1l6Y2dvdmNUQjZSMjl1Tm1Sc09XbHJZWFJWTkVWWWJHaEVVRXQwU0V4SWVIWTVTbGRpVDJ4WlFVUm9jelZvUVhaeFJsQllOM2x0TVZrd2JsUkJQVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=",
          "integratedTime": 1783103666,
          "logIndex": 2063595522,
          "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
        }
      }
    }
  }
]
```

### Tamper Demo (FAILED — correctly)

Output of `cosign verify` on tampered digest:

```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies

```
Verification for localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

### Why digest binding matters (Lecture 8 slide 6)

When an attacker re-tags a malicious image (alpine) to the same tag name (`v20.0.0-tampered`), the image digest changes, and Cosign detects the mismatch — the signature was bound to the original digest, not the tag. If Cosign had signed the tag instead of the digest, the attacker could simply re-tag any malicious image to the signed tag, and verification would succeed — because the tag would remain the same. This is why the lecture emphasizes: **"Cosign signs the digest of the image, not the tag. Tags are mutable; digests aren't."** — this architectural decision is what prevents registry-based image substitution attacks.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (first 30 lines of decoded payload):

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
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
```

- Component count matches Lab 4 source: yes
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: empty output (empty diff = success)

### Provenance attestation

- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)

A "signed but no SBOM" image proves who built it, but gives zero information about what's inside — when the next Log4Shell hits, operators must manually scan every running container to find the vulnerable component. A "signed with SBOM attestation" image allows operators to query attestations across the registry and instantly identify affected images without redeploying or rescanning. At K8s admission time, Kyverno can enforce both the signature and the SBOM predicate, blocking deployment of images without verifiable component inventories — preventing the vulnerable container from ever reaching production, rather than detecting exploitation after the fact.

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
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Error: invalid signature when validating ASN.1 encoded signature
error during command execution: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)

Codecov's bash uploader was distributed via `curl | bash` without verification — a classic build-server compromise (Lecture 8 slide 4). If consumers had run `cosign verify-blob --key codecov-public.pem --bundle bash.bundle bash` before executing the script, the attacker's modified uploader would have failed immediately with "invalid signature" — the same error our tamper test produced. As slide 16 notes, `cosign sign-blob` is the canonical fix for the Codecov 2021 attack pattern.
