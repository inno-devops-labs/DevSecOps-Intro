# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`

### Signing
```
Signing artifact...
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```
All three checks passed: cosign claims validated, transparency log existence verified offline, signature verified against the public key.

### Tamper Demo (FAILED — correctly)
```
Error: no signatures found
error during command execution: no signatures found
```
Tampered image: `localhost:5000/juice-shop:v20.0.0-tampered` (actually `alpine:3.20` re-tagged), resolving to a completely different digest: `sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e`.

### Sanity — original still verifies
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters
Cosign signs the image's content-addressed digest, not the mutable tag pointer. When the tampered image was pushed under the same tag (`v20.0.0-tampered`), it resolved to a completely different digest (it's `alpine:3.20`, not `juice-shop`), so `cosign verify` correctly reported "no signatures found" for that digest. If Cosign had signed the tag instead of the digest, an attacker could re-push arbitrary content under the same tag name and any downstream consumer trusting "this tag is signed" would have accepted the swapped content — because tags are mutable pointers, not content hashes. Digest-binding is what makes the signature actually mean "this exact set of bytes," not "whatever currently happens to sit behind this name."

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` succeeded)
- Verify-attestation: all three checks passed (cosign claims validated, transparency log existence verified offline, signature verified against public key)
- Component count matches Lab 4 source: yes — 1846 components in both the original `labs/lab4/juice-shop.cdx.json` and the SBOM extracted from the attestation

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`
- Decoded predicate:
```json
{
  "buildType": "https://example.com/lab8/local-build",
  "builder": { "id": "https://localhost/lab8-student" },
  "invocation": {
    "configSource": {
      "digest": { "sha1": "abc123" },
      "uri": "https://github.com/karmihkr/DevSecOps-Intro"
    }
  }
}
```

### What this gives a Lab 9 verifier
A "signed but no SBOM" image proves the bytes weren't tampered with, but says nothing about what's inside — if a library like Log4j has a critical CVE, there's no fast way to know whether this specific image is affected without re-scanning it from scratch. A "signed with SBOM" image lets an admission policy (or an incident responder) instantly answer "does this exact deployed artifact contain the vulnerable component?" by querying the attached, cryptographically-bound SBOM — no re-scan, no guessing, no waiting on a vendor to confirm. At K8s admission time, a Kyverno verify-images policy can require both the signature and a specific attestation predicate, turning "we think we're not affected" into "we can prove which images are affected in seconds."

---

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

### Codecov 2021 mitigation
The Codecov bash uploader was fetched via `curl | bash` with no integrity check — anyone who compromised the distribution point could silently swap in a malicious script, which is exactly what happened. If Codecov's users had run `cosign verify-blob --key cosign.pub --bundle uploader.sh.bundle uploader.sh` before executing it, a tampered script would have failed verification immediately (as demonstrated above) because the signature is bound to the exact byte stream of the original file, not to its filename or download URL. The attack would have been caught at the verification step, before a single line of the malicious script ever ran.