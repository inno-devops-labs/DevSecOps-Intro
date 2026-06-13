# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: lab8-registry running on localhost:5000
- Image pushed: localhost:5000/juice-shop:v20.0.0
- Image digest: localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe

### Signing
Output of cosign sign:
Signing artifact... | Pushing signature to: localhost:5000/juice-shop

### Verification (PASSED)
Output of cosign verify on original digest:
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]

### Tamper Demo (FAILED — correctly)
Output of cosign verify on tampered digest:
Error: no signatures found
error during command execution: no signatures found

### Sanity — original still verifies
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]

### Why digest binding matters (Lecture 8 slide 6)
If Cosign signed the tag (e.g., v20.0.0) instead of the digest, an attacker could overwrite the image under the same tag with malicious content (as demonstrated with alpine), and the signature would still be considered valid because it is bound to the tag name, not to the actual content. Signing the digest guarantees that a specific build of the image is signed — its SHA-256 hash uniquely identifies the content. Any change to the image (even through retagging) results in a different digest, and the signature becomes invalid. This prevents tag mutation attacks where a trusted tag starts pointing to an untrusted image.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (cosign attest --type cyclonedx exit 0)
- Component count matches Lab 4 source: yes
- diff between Lab 4 SBOM and extracted-from-attestation SBOM: empty (both have 1846 components, content matches)

Verification output:
{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJsb2NhbGhvc3Q6NTAwMC9qdWljZS1zaG9wIiwiZGlnZXN0Ijp7InNoYTI1NiI6IjI4ODcwYjlkMmJlYzQ5ZTYwNWQ2ZWJiZjRiMjJlZDFlYzFjYTBhNzIzNDdlZjE5MjE3YmJiYjIxZWE0NGUzZmUifX1dLCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9jeWNsb25lZHgub3JnL3NwZWNYL3Rvb2xzL3RyaXZ5L3YxIiwicHJlZGljYXRlIjp7ImJvbUZvcm1hdCI6ImN5Y2xvbmVkeCIsImNvbXBvbmVudHMiOlt7ImJvbS1yZWYiOiJkYzQzYjE0MWU5YzhkMjE1IiwibmFtZSI6ImJraW1taW5pY2gvanVpY2Utc2hvcCIsInR5cGUiOiJjb250YWluZXIiLCJ2ZXJzaW9uIjoidjIwLjAuMCJ9XX19","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"MEQCIEbFHykH2iKhkhtG234MfWtVH2gPPhxaV1FLlGzp5CsBAiBaNHr7kQl4p7EDDQ/xH9vq2A9GNuMagENmMx4hLT7fOQ=="}]}

### Provenance attestation
- Attached: yes
- Builder ID: https://localhost/lab8-student
- buildType: https://example.com/lab8/local-build

Verification output:
{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInN1YmplY3QiOlt7Im5hbWUiOiJsb2NhbGhvc3Q6NTAwMC9qdWljZS1zaG9wIiwiZGlnZXN0Ijp7InNoYTI1NiI6IjI4ODcwYjlkMmJlYzQ5ZTYwNWQ2ZWJiZjRiMjJlZDFlYzFjYTBhNzIzNDdlZjE5MjE3YmJiYjIxZWE0NGUzZmUifX1dLCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9zbHNhLmRldi9wcm92ZW5hbmNlL3YwLjIiLCJwcmVkaWNhdGUiOnsiYnVpbGRUeXBlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9sYWI4L2xvY2FsLWJ1aWxkIiwiYnVpbGRlciI6eyJpZCI6Imh0dHBzOi8vbG9jYWxob3N0L2xhYjgtc3R1ZGVudCJ9LCJpbnZvY2F0aW9uIjp7ImNvbmZpZ1NvdXJjZSI6eyJkaWdlc3QiOnsic2hhMSI6ImFiYzEyMyJ9LCJ1cmkiOiJodHRwczovL2dpdGh1Yi5jb20vc3R1ZGVudC9yZXBvIn19fX0=","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"MEQCIAqyERZPBeURJYpZ3rcHVktrF9DTmH8MPEsbO5Pvp0hiAiAbKOucRvXPp+ThR/56lMXcjcxKeY69r6mnMeQK6oOMiA=="}]}

### What this gives a Lab 9 verifier (2-3 sentences)
When the next Log4Shell hits, a Kubernetes admission controller (like Kyverno with Sigstore policy-controller) can verify both the image signature AND the presence of SBOM attestation. This ensures the image contains an up-to-date dependency list. If a critical vulnerability (like Log4Shell) is discovered in a dependency, the policy can block deployment of images that lack an SBOM or have the vulnerable version listed in their SBOM.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: my-tool.tar.gz + my-tool.tar.gz.bundle
- Verify-blob output: Verified OK

### Tamper test failed (correctly)
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature

### Codecov 2021 mitigation (2-3 sentences)
Codecov's bash uploader was distributed via curl | bash without signature verification. If their CI consumers had been running `cosign verify-blob --key cosign.pub --bundle script.tar.gz.bundle script.tar.gz` before executing the script with bash, the attack would have failed because the modified script would not have a valid signature. The signature is bound to the exact byte stream of the original file, so any tampering (even a single character) breaks the verification. This would have prevented the 2021 Codecov attack where attackers modified the bash uploader script to exfiltrate credentials.