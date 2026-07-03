# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d`

### Signing
- Output of `cosign sign` (just the success line is fine):
```
tlog entry created with index: 2063841657
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"cosign container image signature"},"optional":{"Bundle":{"SignedEntryTimestamp":"MEUCIAkwoJ6ay9nIoZOY9VQcHy6tOAZKvkwoHSVzAbaKPBpcAiEA3Wj9HfUFfwbKW42d+bkVHthZnzTZ2q7FWEPt9tpSh/s=","Payload":{"body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2MzY5MDc0MzhmYTM3YzA3ZDA1ZDhiYmM5MzExMWFkNWY5MmY0ZmE1N2EyNDRjMGY3ODEwZTMxZTM0NzFhNGZmIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJRXJuaUh3SDJqQ3pwVTh3djk3QUIzUUVEbWZ3aG0xYW9zR0lKd2UwdnVoOUFpQkt0REdHcHFhUU5ERUR1VUhnSjU1bnErd241eHE1ZXdRUis3WENML1pKQnc9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGT0N0dFUxbG5SRmQ1YjFsM1UxZDNiMWRRZW5kTk1VUkdjSE4zYWdweU5VWm5XSFJJVlRSYVUwbHZVVTVWUnpGNllqWlNUWGxMV21zeFJGUTBaSEZYZVhsV1EwSXJRM0ZDU1RZNFduWlJhRWh5VVdjNVR6bFJQVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=","integratedTime":1783108022,"logIndex":2063841657,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}}}}]
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies
```
The original digest still passes verification successfully following an attempted unauthorized modification. Signatures are verified using the specified public key.
```

### Why digest binding matters (Lecture 8 slide 6)
2-3 sentences. The tampered re-tag pointed to a DIFFERENT digest; your signature was bound to the
ORIGINAL digest. What would have broken if Cosign had signed the tag instead?

The modified tag pointed to a different Alpine digest, whereas the signature was tied to the original Juice Shop digest. If Cosign had signed the `v20.0.0` tag rather than the digest, an attacker could simply have uploaded a malicious image under the same tag, and the signature would still have been considered valid. Digest-based pinning prevents tag-swapping attacks, the same type of attack as the xz-utils backdoor injection, where a malicious version could replace the original one without being detected.

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
        "sha256": "8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"
      }
    }
  ],
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
    "bomFormat": "CycloneDX",
    "components": [
      {
        "bom-ref": "04d08f08-482e-4939-b763-29784d95eeba",
        "hashes": [
          {
            "alg": "SHA-1",
            "content": "14b52ea8911e4e9f89acb4d876e87755e54529e2"
          }
        ],
        "licenses": [
          {
            "license": {
              "id": "ISC"
            }
          }
        ],
```
- Component count matches Lab 4 source: yes 
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `<empty diff>` (empty diff = succes)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
Lecture 8 slide 12 + Lecture 9 slide 4 — at K8s admission time, a Kyverno verify-images policy
can require BOTH signatures AND specific attestation predicates. What's the operational difference
between a "signed but no SBOM" image and a "signed with SBOM" image when the next Log4Shell hits?

Using a signed image that lacks an SBOM forces operators to manually check every deployed instance for the Log4j vulnerability, turning the task into a frantic, hours-long scramble. An image with a signed SBOM enables Kyverno to read the embedded component list during the admission phase and automatically block vulnerable images. With an SBOM, incident response shifts from manual searching to automated policy enforcement.