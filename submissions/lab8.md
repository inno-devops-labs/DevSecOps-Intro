# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`

### Signing
- Output of `cosign sign` (just the success line is fine):
```
tlog entry created with index: 2063533592
Pushing signature to: localhost:5000/juice-shop
```
### Verification (PASSED)
Output of `cosign verify` on original digest:
```
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"cosign container image signature"},"optional":{"Bundle":{"SignedEntryTimestamp":"MEUCIB1IS0zl1eP4/Za6qwSlbEFpUBhR+rV3RnGsquYNwuZcAiEA1ImaTGFNxCMc8d2YTWwuvuP3NlHV4Z25EybhleAYUKo=","Payload":{"body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI3OTgwNzhjNTlhMGYxNjdiYWFhYTc4ZjkwM2E3MWIwZGI5NThhMTk3ZWU1ZGZiOWIzNTA0ZTQ2MzAwNWQ0MTlhIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUURrZkZtSFRacFNXZENYSE1QeTllT1EzRXJCRWtSK0Y2S05Tb3c2OWhLQkNBSWhBTk1ZeTV5RjNVRjJwWXhjUUlkL1RPY3RNY2d3R0c2NGJvN2l4Z3MwZHNDSSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGVkhGWUwwVkpSVzl3UWtsMk1WWlNhak5sWWpkUWVFRnZNMWRUTWdwTWMwNUtjbm94TkRsbFJVVlVTMW92UWpaMldHUm9OMmhCYTNndkx6bEJPQ3RtVkROU0swTTFSRzFPWkhCR1VVMDRVVWhLT1dNNVNHbFJQVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=","integratedTime":1783101165,"logIndex":2063533592,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}}}}]
```
### Tamper Demo (FAILED — correctly)
Output of cosign verify on tampered digest:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```
### Sanity — original still verifies
```
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"cosign container image signature"},"optional":{"Bundle":{"SignedEntryTimestamp":"MEUCIB1IS0zl1eP4/Za6qwSlbEFpUBhR+rV3RnGsquYNwuZcAiEA1ImaTGFNxCMc8d2YTWwuvuP3NlHV4Z25EybhleAYUKo=","Payload":{"body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI3OTgwNzhjNTlhMGYxNjdiYWFhYTc4ZjkwM2E3MWIwZGI5NThhMTk3ZWU1ZGZiOWIzNTA0ZTQ2MzAwNWQ0MTlhIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUURrZkZtSFRacFNXZENYSE1QeTllT1EzRXJCRWtSK0Y2S05Tb3c2OWhLQkNBSWhBTk1ZeTV5RjNVRjJwWXhjUUlkL1RPY3RNY2d3R0c2NGJvN2l4Z3MwZHNDSSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGVkhGWUwwVkpSVzl3UWtsMk1WWlNhak5sWWpkUWVFRnZNMWRUTWdwTWMwNUtjbm94TkRsbFJVVlVTMW92UWpaMldHUm9OMmhCYTNndkx6bEJPQ3RtVkROU0swTTFSRzFPWkhCR1VVMDRVVWhLT1dNNVNHbFJQVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=","integratedTime":1783101165,"logIndex":2063533592,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}}}}]
```

### Why digest binding matters (Lecture 8 slide 6)
2-3 sentences. The tampered re-tag pointed to a DIFFERENT digest; your signature was bound to the ORIGINAL digest. What would have broken if Cosign had signed the tag instead?

If Cosign had signed the tag instead of the digest, the tampered image would have passed verification because the tag would still point to the same name, even though the content had changed. When we bind the signature to the digest, any attempt to replace the image with a different one fails verification, because the new digest does not match the signed one.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (first 30 lines of decoded payload):
```json
{
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
```
Component count matches Lab 4 source: yes
diff between Lab 4 SBOM and the extracted-from-attestation SBOM:

### Provenance attestation
Attached: yes
Builder ID in predicate: `https://github.com/RC-5555`
buildType in predicate: `https://github.com/RC-5555/DevSecOps-Intro/lab8`

### What this gives a Lab 9 verifier (2-3 sentences)
Lecture 8 slide 12 + Lecture 9 slide 4 — at K8s admission time, a Kyverno verify-images policy can require BOTH signatures AND specific attestation predicates. What's the operational difference between a "signed but no SBOM" image and a "signed with SBOM" image when the next Log4Shell hits?

When the next Log4Shell hits, you don't know whether a "signed but no SBOM" image contains a vulnerable library, but with a "signed with SBOM" image you can immediately check if the affected component is present. If that's the case, the Kyverno policy lets you block deployment.