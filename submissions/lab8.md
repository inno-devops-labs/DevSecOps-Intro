# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d`

### Signing
Output of `cosign sign`:
```
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
Error: no signatures found
```

### Sanity — original still verifies
```
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

### Why digest binding matters (Lecture 8 slide 6)

The signature is cryptographically bound to the digest (sha256), not the tag (`:v20.0.0`). If Cosign had signed the tag instead, an attacker could re-tag a different image (like `alpine:3.20`) with the same `:v20.0.0` tag and the signature would still appear valid — tag mutation is trivial, but digest modification requires breaking SHA-256. The tamper demo proves this: the re-tagged alpine image has a different digest, and `cosign verify` correctly returns "no signatures found" because the signature is anchored to the original digest.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (decoded payload summary):
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [{"name": "localhost:5000/juice-shop", "digest": {"sha256": "8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"}}],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "components_count": 3069
  }
}
```
- Component count matches: yes (3069 = 3069)
- diff between SBOMs: `IDENTICAL` (empty diff = success)

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)

At K8s admission time, a Kyverno `verify-images` policy can require both a valid signature AND specific attestation predicates. A "signed but no SBOM" image only proves authenticity of the publisher — it does not reveal what dependencies are inside. A "signed with SBOM" image allows the policy to block deployments with known-vulnerable components (e.g., a Log4Shell-affected Log4j version), because the SBOM predicate is cryptographically bound to the image digest and can be inspected at admission.

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
```

### Codecov 2021 mitigation (2-3 sentences)

Codecov's bash uploader was distributed via `curl | bash` without signature verification — attackers replaced the legitimate script with a malicious one that exfiltrated credentials from CI environments. If consumers had run `cosign verify-blob --key publisher.pub --bundle script.sh.bundle script.sh` before piping to `bash`, the tampered script's signature would have failed verification (as demonstrated above), preventing the attack. The `cosign sign-blob` and `cosign verify-blob` pattern creates a detached signature bundle that travels alongside the artifact, enabling cryptographic verification at the point of consumption regardless of the transport channel.
