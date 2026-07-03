# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d`

### Signing
- Output of `cosign sign`:
```
Signing artifact...
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
error during command execution: no signatures found
```

### Sanity — original still verifies
```
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters (Lecture 8 slide 6)
Cosign signs the digest (`@sha256:...`), not the tag (`:v20.0.0`). Tags are mutable — anyone can re-tag a different image with the same tag. If Cosign signed the tag instead, re-tagging alpine as juice-shop would still pass verification. Digest binding ensures the signature is cryptographically tied to the exact image content, making tag-mutation attacks detectable.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (first lines of decoded payload):
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [{
    "name": "localhost:5000/juice-shop",
    "digest": {"sha256": "8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"}
  }],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [...]
  }
}
```
- Component count matches Lab 4 source: **yes** (3069 components)
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `<empty — no diff, exact match>`

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
At K8s admission time, a Kyverno verify-images policy can require both a valid signature AND attestations with specific predicates. A "signed but no SBOM" image proves who built it but not what's inside — when the next Log4Shell hits, you cannot query which images depend on Log4j. A "signed with SBOM" image allows the verifier to reject deployments that contain vulnerable components before they ever reach production.

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

### Codecov 2021 mitigation (2-3 sentences)
Codecov's bash uploader was distributed via `curl | bash` without signature verification. Consumers downloaded the script and piped it directly to bash with no integrity check — when the attacker modified the uploader on Codecov's infrastructure, every CI pipeline that ran `curl https://codecov.io/bash | bash` executed the attacker's payload. If consumers had been running `cosign verify-blob --key distributor.pub --bundle uploader.sh.bundle uploader.sh` before piping to bash, the signature verification would have failed because the attacker's modified uploader had a different hash than the one the signature was bound to, stopping the attack at the verification step (Lecture 8 slide 14).