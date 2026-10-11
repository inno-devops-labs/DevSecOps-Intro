# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d`

### Signing
```
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"cosign container image signature"},"optional":null}]
```

### Tamper Demo (FAILED — correctly)
Pushed `alpine:3.20` re-tagged as `localhost:5000/juice-shop:v20.0.0-tampered` (digest `sha256:6c2a97...`):
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies
```
Verification for localhost:5000/juice-shop@sha256:8c76bce... --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},...},"optional":null}]
```

### Why digest binding matters (Lecture 8 slide 6)
Cosign signs the **immutable content-addressable digest** (`sha256:8c76...`), not the mutable tag string `v20.0.0`. When the attacker pushed `alpine:3.20` under the same tag, it got a completely different digest (`sha256:6c2a97...`) — and Cosign found no signature attached to that digest in the registry. If Cosign had signed the tag instead, any image pushed under that tag label would inherit the "valid signature" status, making the tamper completely undetectable. Digest binding ensures that what you signed is exactly what runs — not just a name that any image can occupy.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation decoded payload:
```json
{
  "type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "components": 3069
}
```
- Component count matches Lab 4 source: **yes** (3069 = 3069)
- diff between Lab 4 SBOM and extracted-from-attestation SBOM: *(empty — identical content)*

### Provenance attestation
- Attached: yes (`cosign attest --type slsaprovenance` exit 0)
- Builder ID: `https://localhost/lab8-student`
- buildType: `https://example.com/lab8/local-build`
- Verified decoded payload:
```json
{
  "type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "builder": "https://localhost/lab8-student"
}
```

### What this gives a Lab 9 verifier
A "signed but no SBOM" image tells you the bytes haven't been tampered with since signing — but when the next Log4Shell drops at 2 AM, you still have to pull every running image and re-scan it to know which services use the vulnerable library. A "signed with SBOM" image carries the full component inventory *as a verifiable attestation*: a Kyverno policy in Lab 9 can run `cosign verify-attestation --type cyclonedx` at admission time and compare the embedded SBOM against a known-bad package list before the pod starts — no re-scan required. The SBOM attestation turns a reactive "did we ship Log4j?" fire drill into a proactive O(1) lookup against a cryptographically verified manifest.

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success:
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)
After appending `"MALICIOUS PAYLOAD"` to the tarball:
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Error: invalid signature when validating ASN.1 encoded signature
error during command execution: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation
In the Codecov attack (Lecture 8 slide 14), attackers modified the bash uploader script distributed at a static URL — consumers downloading via `curl | bash` had no way to detect the substitution because there was no integrity check. If Codecov had published a Cosign bundle alongside the script and documented the verification step, any CI consumer running:
```bash
cosign verify-blob --key codecov.pub --bundle codecov-uploader.bundle codecov-uploader.sh
```
would have received `Error: invalid signature` immediately — the attacker's modified bytes would not match the signature Codecov produced over the legitimate bytes. The key insight from Lecture 8 slide 14 is that `cosign sign-blob` binds the signature to the exact byte sequence, so even a single-byte change (like the attacker's injected credential-exfiltration payload) causes verification to fail before the script ever executes.
