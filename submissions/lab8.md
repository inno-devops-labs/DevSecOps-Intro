# Lab 8 — Supply Chain Security: Cosign Sign + SBOM Attestation + Blob Signing

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5001`
- Image pushed: `localhost:5001/juice-shop:v20.0.0`
- Image digest: `localhost:5001/juice-shop@sha256:760042c54214cbb86f6009bd56218b6bac11044605b51d0c4478a5a384106365`

### Signing
```
Signing artifact... - Pushing signature to: localhost:5001/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.

Verification for localhost:5001/juice-shop@sha256:760042c54214cbb86f6009bd56218b6bac11044605b51d0c4478a5a384106365 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5001/juice-shop@sha256:760042c54214cbb86f6009bd56218b6bac11044605b51d0c4478a5a384106365"},"image":{"docker-manifest-digest":"sha256:760042c54214cbb86f6009bd56218b6bac11044605b51d0c4478a5a384106365"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demo (FAILED — correctly)
Tampered image: `alpine:3.20` re-tagged as `localhost:5001/juice-shop:v20.0.0-tampered`
Tampered digest: `alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`

Output of `cosign verify` on tampered digest:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies
Running `cosign verify` on the original digest after the tamper attempt returned the same successful JSON payload as above — the signature is digest-bound, not tag-bound, so it remained valid.

### Why digest binding matters (Lecture 8 slide 6)
If Cosign had signed the tag `:v20.0.0` instead of the digest `@sha256:760042...`, an attacker who gained write access to the registry could re-point the tag to a malicious image and the existing signature would appear to validate it — because the signature would be bound to the tag string, not the content. By binding the signature to the immutable content digest, re-tagging is irrelevant: the tampered alpine image has a completely different digest (`sha256:d9e853...`) and Cosign correctly reports "no signatures found" because no signature exists for that content hash. This is why supply chain security tools always work at the digest level — tags are mutable pointers, digests are content hashes.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (decoded payload summary):
```json
{
  "type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "componentCount": 3068
}
```
- Component count matches Lab 4 source: **yes** — 3068 components in both
- The attestation predicate is the exact `juice-shop.cdx.json` from Lab 4, wrapped in an in-toto Statement v0.1 envelope and stored as an OCI artifact in the local registry alongside the image manifest.

### What this gives a Lab 9 verifier
When the next Log4Shell-class vulnerability drops, a "signed but no SBOM" image requires someone to manually pull the image, run Syft or Trivy, and check whether the vulnerable library is present — a process that takes hours across a large fleet and is error-prone. A "signed with SBOM" image lets a verifier (Kyverno, policy-controller, or a custom admission webhook) query the attached CycloneDX attestation at admission time and answer "does this image contain log4j-core < 2.15.0?" in milliseconds, without pulling the image layers. The operational difference is the difference between a reactive scramble and a proactive policy gate: with the SBOM attestation in the registry, you can write a Kyverno `verify-images` policy that requires both a valid signature AND a clean SBOM attestation before a pod is admitted to the cluster, turning a 48-hour incident response into a sub-second enforcement decision.

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` → bundle written to `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation
In the Codecov 2021 attack, the attacker modified the bash uploader script distributed via `curl https://codecov.io/bash | bash` — CI pipelines downloaded and executed the tampered script without any integrity check. If Codecov's CI consumers had been running `cosign verify-blob --key codecov.pub --bundle codecov-uploader.bundle codecov-uploader.sh` before executing the script, the attack would have failed at the verification step: the attacker's modified bytes would produce a different SHA-256 hash than the one Cosign signed, causing `verify-blob` to exit non-zero with "invalid signature" and aborting the pipeline before the malicious script ran. The specific Cosign command that would have caught it is exactly the pattern demonstrated above — `cosign verify-blob` with a pre-distributed public key and bundle file, which cryptographically ties the expected content hash to the publisher's signing key and detects any byte-level modification regardless of how the file was distributed.
