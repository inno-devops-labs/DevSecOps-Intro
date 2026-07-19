# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe


### Signing
- Output of `cosign sign` (just the success line is fine):
```

Signing artifact... / Pushing signature to: localhost:5000/juice-shop

```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}},{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]

```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
cosign : WARNING: Skipping tlog verification is an insecure practice that lacks tr
ansparency and auditability verification for the signature.
строка:1 знак:1
+ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog  ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (WARNING: Skippi... the signature.:St 
   ring) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 
Error: no signatures found
error during command execution: no signatures found

```

### Sanity — original still verifies
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.

Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:2887
0b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-man
ifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e
3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}},{"critical":{"id
entity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]

```

### Why digest binding matters (Lecture 8 slide 6)
2-3 sentences. The tampered re-tag pointed to a DIFFERENT digest; your signature was bound to the
ORIGINAL digest. What would have broken if Cosign had signed the tag instead?

If Cosign had signed the tag instead of the digest, the signature would have been permanently broken as soon as the tag was moved. This is because tags are mutable - they can be pointed to a different image without changing the tag name, so the signature would still verify against the new, untrusted content. By signing the immutable digest, the signature is cryptographically bound to the exact bits of the original image, so any change to the content (even if the tag is reused) will cause verification to fail, guaranteeing the integrity of the specific artifact you signed.

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
```
- Component count matches Lab 4 source: yes
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `empty` (empty diff = success)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: https://localhost/lab8-student

- buildType in predicate: https://example.com/lab8/local-build

### What this gives a Lab 9 verifier (2-3 sentences)
Lecture 8 slide 12 + Lecture 9 slide 4 — at K8s admission time, a Kyverno verify-images policy
can require BOTH signatures AND specific attestation predicates. What's the operational difference
between a "signed but no SBOM" image and a "signed with SBOM" image when the next Log4Shell hits?

A signed image without SBOM only proves authenticity but provides no visibility into its contents. When a new zero-day like Log4Shell is disclosed, an SBOM enables immediate automated detection of vulnerable images across the entire cluster, while a signature alone forces manual, time-consuming forensic investigation.

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
cosign : WARNING: Skipping tlog verification is an insecure practice that lacks tr 
ansparency and auditability verification for the blob.
строка:1 знак:1
+ cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle -- ...        
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (WARNING: Skippi...n for the blob.:St  
   ring) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

Error: failed to verify signature: could not verify message: invalid signature whe 
n validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify messa 
ge: invalid signature when validating ASN.1 encoded signature

```

### Codecov 2021 mitigation (2-3 sentences)
Codecov's bash uploader was distributed via `curl | bash` without signature verification.
If their CI consumers had been running `cosign verify-blob` before `bash`-ing the script,
how would the attack have failed? Reference Lecture 8 slide 14 + the specific cosign command
that would have caught it.

If CI consumers had run cosign verify-blob --key <public-key> codecov.sh before executing it, the attack would have failed because the tampered script lacked a valid signature and would have been rejected immediately. Unlike the xz case, where the attacker controlled the maintainer's signing identity, the Codecov attacker did not possess the private signing key, so cosign verification would have blocked execution before any credentials could be exfiltrated.