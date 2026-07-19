# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:7cc03b0e0b5b622f82834fab6ee428a4ca2de5853f9ece07e7ade795e3834271`

### Signing
- Output of `cosign sign` (just the success line is fine):
```
tlog entry created with index: 2138921334
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:7cc03b0e0b5b622f82834fab6ee428a4ca2de5853f9ece07e7ade795e3834271"},"type":"cosign container image signature"},"optional":{"Bundle":{"SignedEntryTimestamp":"MEUCIQD2N/cteSJxILttOAGrcJe2vcKeTDhmK569TVyHofU/XQIgbsa4oHPMpi5VYInPygQ6v2Hss4nxOuiuTNJoZUdDboc=","Payload":{"body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJhMTk0MmEwNzZmNWY2YjMxZWZmNWExNDNmMjYyMzFkNzI1NjUxNDJiN2JlOTcwYmZkNmM5NWE2MDBjYzNmMGFhIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJUURHU1hNYkNOMWhEZHBVL0cvNVNLalpVUDUvOGZ0ZUpPU1BuV29sS1dFSlpnSWdORDhOYWRucGxva0RUQ2V6Z2xpdGtxaUdUMUgwVEtBeHpxSmIybkdqQ1k0PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGWjFoSVpXc3hlR05vVlhKRU1tTldTbGN4UjJkWk5rOUdTa1ZrUlFwdVEydzBVbHBPVW5STWF5dExaVlk0UTJGbFZXRlJiMlpDVVdGaWVVNWhURmxLV0ZWVFV5dHRVMVZtVVVVeldFeE9lRFpuVm1OUEwyMW5QVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=","integratedTime":1783712137,"logIndex":2138921334,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}}}}]
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
main.go:69: error during command execution: no signatures found
```

### Sanity — original still verifies
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.        

Verification for localhost:5000/juice-shop@sha256:7cc03b0e0b5b622f82834fab6ee428a4ca2de5853f9ece07e7ade795e3834271 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

### Why digest binding matters (Lecture 8 slide 6)
If Cosign signed the tag instead, the tampered image re-tagged as `v20.0.0-tampered` would have verified successfully. Bounding the signature to a mutable tag name allows an attacker to completely bypass the integrity check.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes
- Verify-attestation output (first 30 lines of decoded payload):
Note: the output doesn't show `_type`, `subject`, and `predicateType` because the given command filtered for 
`.predicate`. As the consequence, the json file consists only of predicacte with components. 
```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "serialNumber": "urn:uuid:c9f730f3-8484-493e-b1dd-573b77aff8b3",
    "version": 1,
    "metadata": {
      "timestamp": "2026-07-03T21:55:10+03:00",
      "tools": {
        "components": [
          {
            "type": "application",
            "author": "anchore",
            "name": "syft",
            "version": "1.46.0"
          }
        ]
      },
      "component": {
```
- Component count matches Lab 4 source: yes
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: empty diff

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)

When Log4Shell hits, you can instantly check the SBOM to see if Log4j is present and let Kyverno block the image before it runs. Without the SBOM, you have to scan the image or wait for an alert - by then the vulnerable container might already be live.