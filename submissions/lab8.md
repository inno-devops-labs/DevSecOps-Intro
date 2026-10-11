# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest:
```
localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d
```

### Signing
```
cosign sign --key labs/lab8/keys/cosign.key --yes "$DIGEST"
# succeeded, no errors — image pushed to localhost:5000/juice-shop:sha256-8c76bce9...sig
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"cosign container image signature"},"optional":null}]
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest (`localhost:5000/juice-shop:v20.0.0-tampered`, an `alpine:3.20` image re-tagged to impersonate Juice Shop):
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
main.go:69: error during command execution: no signatures found
```

### Sanity — original still verifies
```json
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"cosign container image signature"},"optional":null}]
```

### Why digest binding matters (Lecture 8 slide 6)
Cosign's signature is bound to the immutable content digest (`sha256:8c76bce9...`), not to the mutable tag `v20.0.0`. When `alpine:3.20` was re-tagged as `juice-shop:v20.0.0-tampered`, it resolved to a completely different digest, so the verifier correctly reported `no signatures found` instead of falsely validating unrelated content. If Cosign had signed the tag instead of the digest, an attacker who can push to the registry could repoint `v20.0.0` at any malicious image and the old signature would still "apply" to the tag name, verifying a payload that was never actually signed — this is exactly the tag-mutation attack class digest-binding is designed to prevent.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (decoded envelope metadata):
```json
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the attestation.
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"
      }
    }
  ]
}
```
- Component count matches Lab 4 source: **yes**
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM:
```
$ diff <(jq -S '.components | length' labs/lab4/juice-shop.cdx.json) \
       <(jq -S '.components | length' labs/lab8/results/sbom-from-attestation.json)
# (empty output, exit code 0 — both report 3069 components)
```

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`
- Verify output:
```json
Using payload from: /tmp/predicate-only.json
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the attestation.
Verification for localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
{"payloadType":"application/vnd.in-toto+json","payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjAuMiIsInN1YmplY3QiOlt7Im5hbWUiOiJsb2NhbGhvc3Q6NTAwMC9qdWljZS1zaG9wIiwiZGlnZXN0Ijp7InNoYTI1NiI6IjhjNzZiY2U5NDg5NjViY2IyYWQzM2MyNGE2NTlkNThmMzA3ZDY3OWZmNDhlYzI1M2EzZDI5MTM4MzI5ZjNjMGQifX1dLCJwcmVkaWNhdGUiOnsiYnVpbGRlciI6eyJpZCI6Imh0dHBzOi8vbG9jYWxob3N0L2xhYjgtc3R1ZGVudCJ9LCJidWlsZFR5cGUiOiJodHRwczovL2V4YW1wbGUuY29tL2xhYjgvbG9jYWwtYnVpbGQiLCJpbnZvY2F0aW9uIjp7ImNvbmZpZ1NvdXJjZSI6eyJ1cmkiOiJodHRwczovL2dpdGh1Yi5jb20vc3R1ZGVudC9yZXBvIiwiZGlnZXN0Ijp7InNoYTEiOiJhYmMxMjMifX19fX0=","signatures":[{"keyid":"","sig":"MEQCICONZ8maXclvwALWqQJoeictesIdUircusGy+7sgLXrwAiBMOUU/imQJOpM5Vu1W1gXhMfoq2kbtKaROsWEVPnmLsQ=="}]}
```

### What this gives a Lab 9 verifier (2-3 sentences)
A "signed but no SBOM" image only proves the bytes weren't tampered with in transit — it says nothing about *what's inside*. A "signed with SBOM" image lets a Kyverno `verify-images` policy pull the attached CycloneDX predicate at admission time and answer "does this running image contain package X at version Y" without needing to re-scan the filesystem or trust an out-of-band inventory. When the next Log4Shell-class CVE drops, a fleet with signed SBOM attestations can be queried in minutes (`is log4j-core:2.14.1 anywhere in my signed images?`) instead of days of ad-hoc scanning, and any image lacking a valid attestation can be automatically blocked from deployment until it's rebuilt and re-attested.

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`

Sign output:
```
Using payload from: labs/lab8/results/my-tool.tar.gz
Enter password for private key:
tlog entry created with index: 2063250742
Wrote bundle to file labs/lab8/results/my-tool.tar.gz.bundle
MEUCIEKrG5cGl31xJtN++WdwbfA8n1fg07lPsTFcR0Aw+zACAiEAxxJ9IqZHUnMVdFnN9XeWGAzd6uDh5swUqXLNYtwmwXc=
```

Verify-blob success output (on a fresh copy in `/tmp/fresh-download/`, simulating a clean download):
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)
After appending `MALICIOUS PAYLOAD` to the downloaded tarball and re-running `cosign verify-blob` against the original bundle:
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Error: invalid signature when validating ASN.1 encoded signature
main.go:74: error during command execution: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)
The Codecov bash uploader was fetched via `curl | bash` and executed with zero integrity checking, so when attackers modified the script on Codecov's infrastructure, every downstream CI pipeline silently ran the tampered version and leaked credentials. If consumers had instead run `cosign verify-blob --key cosign.pub --bundle uploader.sh.bundle uploader.sh` before executing it, the signature check would have failed the moment a single byte of the script changed — exactly as demonstrated above, where appending one line to `my-tool.tar.gz` turned a passing `Verified OK` into an `invalid signature` error. The fix isn't exotic: `verify-blob` before `bash` converts a silent supply-chain compromise into a loud, blocking CI failure.
