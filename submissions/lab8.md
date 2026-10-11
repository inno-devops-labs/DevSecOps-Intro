# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`

### Signing
- Output of `cosign sign` (just the success line is fine):
    ```
    Signing artifact... | Pushing signature to: localhost:5000/juice-shop
    ```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies
```
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters (Lecture 8 slide 6)
According to Lecture 8, slide 6, tags are mutable, while digests are immutable. If Cosign had signed the tag instead of the digest, an attacker could retag a different image under the same tag without invalidating the signature. Binding the signature to the immutable digest ensures that any change to the image content causes signature verification to fail.

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
    ```
- Component count matches Lab 4 source: **yes**
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `` (empty)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-semyonnadutkin`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
Images signed without an SBOM only prove the authenticity of the image. Images signed with an SBOM also provide a trusted inventory of the software components they contain. When a new vulnerability (e.g. Log4Shell) is disclosed, a Kyverno policy can use the SBOM attestation to enforce supply chain policies and reject deployments that do not meet the required security criteria.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
Verified OK
```

### Tamper test failed (correctly)
```
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)
Codecov's modified bash uploader would not have passed signature verification, so the CI pipeline would have rejected it before executing `bash`. Running `cosign verify-blob --key <key>.pub --bundle <script>.bundle <script>` would have detected that the downloaded script did not match the signed version. As discussed in Lecture 8 (slide 14), signature verification helps ensure artifact integrity before execution, preventing tampered files from being trusted.
