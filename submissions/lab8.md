# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push

- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`

### Signing

- Output of `cosign sign` (just the success line is fine):

```text
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)

Output of `cosign verify` on original digest:

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      },
      "image": {
        "docker-manifest-digest": "sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      },
      "type": "https://sigstore.dev/cosign/sign/v1"
    },
    "optional": {}
  }
]
```

### Tamper Demo (FAILED — correctly)

Output of `cosign verify` on tampered digest:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies

```text
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters (Lecture 8 slide 6)

If Cosign had signed the mutable tag (`:v20.0.0`) instead of the immutable digest (`@sha256:...`), an attacker could simply pull a malicious image (like Alpine), re-tag it as `localhost:5000/juice-shop:v20.0.0`, and push it. Because the signature would be tied to the tag name rather than the cryptographic hash of the image layers, the verification step would falsely validate the attacker's malicious payload as the legitimate Juice Shop image. Digest binding ensures the signature is mathematically locked to the exact bytes of the original image.

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

- Component count matches Lab 4 source: **yes**
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `<empty>` (empty diff = success)

### Provenance attestation

- Attached: yes (Note: used `--signing-config` to disable Rekor in Cosign v3)
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)

A "signed but no SBOM" image only proves who built it, meaning if Log4Shell drops, security teams must manually pull and scan every image to see if it contains the vulnerable library. A "signed with SBOM" image allows a K8s admission controller (like Kyverno in Lab 9) to query the signed attestation metadata to identify which deployments contain Log4j, enabling immediate, automated remediation without scanning the actual container layers.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify

- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)

In the 2021 Codecov attack, the bash uploader was distributed via `curl | bash` without any cryptographic verification, allowing an attacker to inject a malicious payload into the script. If CI pipelines had been using `cosign verify-blob` against a published signature bundle before executing the script, the modified malicious payload would have failed the cryptographic check (as demonstrated in the tamper test), halting the attack immediately before any credentials were exfiltrated.
