# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`

### Signing
- Output of `cosign sign` (just the success line is fine):
```
Signing artifact...
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"cosign container image signature"},"optional":null}]
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
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"cosign container image signature"},"optional":null}]
```

### Why digest binding matters (Lecture 8 slide 6)
In the tamper demo, Alpine was re-tagged and pushed under a similar name, but its digest (`sha256:c64c687c...`) is different from the signed Juice Shop digest (`sha256:28870b9...`). Cosign signs the digest (`@sha256:...`), not the tag — Lecture 8 slide 6: tags are mutable, digests are not. If Cosign signed only the tag, an attacker could overwrite `:v20.0.0` in the registry with a malicious image and verification would still pass, because the tag name would match even though the content changed.

---

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
        "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
    "bomFormat": "CycloneDX",
    "components": [
      {
        "author": "Benjamin Byholm <bbyholm@abo.fi> (https://github.com/kkoopa/), Mathias Küsel (https://github.com/mathiask88/)",
        "bom-ref": "pkg:npm/1to2@1.0.0?package-id=3cea2309a653e6ed",
        "cpe": "cpe:2.3:a:nodejs:1to2:1.0.0:*:*:*:*:*:*:*",
        "description": "NAN 1 -> 2 Migration Script",
        ...
      }
    ]
  }
}
```
- Component count matches Lab 4 source: yes (Lab 4: 1846, attestation: 1846)
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `` (empty diff = success)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
In Lab 9, Kyverno can require both a valid Cosign signature and specific attestations before a Pod is admitted. A signed image without an SBOM only proves who built it — not what libraries are inside. A signed image with a CycloneDX SBOM lets you search deployed images for a vulnerable dependency (e.g. Log4j) in minutes when the next Log4Shell hits.

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: invalid signature when validating ASN.1 encoded signature
error during command execution: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)
In the Codecov 2021 incident, CI pipelines ran the bash uploader via `curl | bash` with no signature check. Running `cosign verify-blob --key cosign.pub --bundle uploader.bundle uploader.sh` before execution would fail on the tampered script. The pipeline would stop instead of running the attacker's code.
