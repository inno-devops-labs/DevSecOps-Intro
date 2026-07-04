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
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.  
  
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --  
The following checks were performed on each of these signatures:  
 - The cosign claims were validated  
 - Existence of the claims in the transparency log was verified offline  
 - The signatures were verified against the specified public key  
  
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"  
docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":  
{}}]
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
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.  
  
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --  
The following checks were performed on each of these signatures:  
 - The cosign claims were validated  
 - Existence of the claims in the transparency log was verified offline  
 - The signatures were verified against the specified public key  
  
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"  
docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":  
{}}]
```

### Why digest binding matters (Lecture 8 slide 6)

The tampered re-tag pointed to a DIFFERENT digest; your signature was bound to the ORIGINAL digest. What would have broken if Cosign had signed the tag instead? If Cosign had signed the tag (like `v20.0.0`) instead of the digest, the tamper demo would have falsely PASSED verification. Because Docker tags are mutable (can be easily moved to another image), an attacker could push a malicious image with the same tag, and the verification system would trust it since the tag itself would still have a valid signature. Binding the signature to the immutable sha256 digest ensures that even a single altered byte in the image invalidates the signature.

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
- Component count matches Lab 4 source: yes / no
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `no output` (empty diff = success)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)

A "signed but no SBOM" image only guarantees that the image hasn't been modified since the developer pushed it. However, a "signed with SBOM" image provides a cryptographically verified list of all internal components. When a new zero-day like Log4Shell hits, an admission controller (like Kyverno) can automatically inspect the verified SBOM attestation and block the deployment if a vulnerable component is listed, without having to rescan the entire image.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob. Verified OK
```

### Tamper test failed (correctly)
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob. Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)

If CI pipelines had downloaded the Codecov bash uploader alongside a Cosign bundle and public key, they could have run `cosign verify-blob --key cosign.pub --bundle uploader.bundle uploader.sh` before executing it. Because the attackers modified the bash script directly on Codecov's servers without having access to the private signing key, the new tampered script would generate a mismatched hash. The `verify-blob` command would have immediately failed with an "invalid signature" error (just like in our tamper test), halting the pipeline before the malicious code could run and steal environment variables.
