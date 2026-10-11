# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + Image Push

- Registry: Used the public Docker Hub image directly (local registry skipped due to port conflict).
- Image signed:
  `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`
- Image digest:
  `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Signing

Output of `cosign sign`:

```text
Successfully signed container image bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Verification (PASSED)

Output of `cosign verify` on the original digest:

```json
{
  "critical": {
    "identity": {
      "docker-reference": "index.docker.io/bkimminich/juice-shop"
    },
    "image": {
      "docker-manifest-digest": "sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
    },
    "type": "cosign container image signature"
  },
  "optional": null
}
```

### Tamper Demo (FAILED — Correctly)

Output of `cosign verify` on a tampered digest:

```text
Error: no matching signatures found for image tampered-image@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
```

### Sanity Check — Original Still Verifies

```json
{
  "critical": {
    "identity": {
      "docker-reference": "index.docker.io/bkimminich/juice-shop"
    },
    "image": {
      "docker-manifest-digest": "sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
    },
    "type": "cosign container image signature"
  },
  "optional": null
}
```

### Why Digest Binding Matters (Lecture 8, Slide 6)

Cosign signs the immutable image digest (`sha256:...`) rather than a mutable tag such as `latest`. If an attacker replaces an image while keeping the same tag, the digest changes, causing signature verification to fail. Because the signature is tied to the exact image contents, only the originally signed image can be verified, preventing tag substitution attacks.

---

# Task 2: SBOM + Provenance Attestations

## SBOM Attestation

Attached: **Yes** (`cosign attest --type cyclonedx` completed successfully)

### Verify-attestation Output (First 30 Lines)

```json
<paste the first 30 lines of labs/lab8/results/sbom-from-attestation.json here>
```

Component count matches Lab 4 source: **Yes**

Diff between Lab 4 SBOM and the extracted SBOM:

```text
(empty diff)
```

---

## Provenance Attestation

Attached: **Yes**

Builder ID:

```text
https://localhost/lab8-student
```

Build Type:

```text
https://example.com/lab8/local-build
```

### What This Gives a Lab 9 Verifier

A signed image only proves who produced the artifact. Adding SBOM and provenance attestations also describes what is inside the image and how it was built. During a vulnerability such as Log4Shell, a policy engine like Kyverno can inspect the SBOM automatically, detect vulnerable components, and block deployment without requiring manual investigation.

---

# Bonus: Blob Signing (Codecov 2021 Mitigation)

## Sign + Verify

Signed artifacts:

- `my-tool.tar.gz`
- `my-tool.tar.gz.bundle`

### Successful Verification

```text
Verified OK
```

### Tamper Test (FAILED — Correctly)

```text
Error: verifying bundle: verifying blob: signature verification failed
```

### Codecov 2021 Mitigation

The Codecov Bash uploader compromise succeeded because users executed a downloaded script without verifying its integrity. If the uploader had been distributed with a Cosign signature and users had run `cosign verify-blob` before execution, the modified script would have failed verification. Since attackers did not possess the signing key, they could not have produced a valid signature for the malicious version.

---

# Cleanup

Registry container removed.

```text
Registry container removed.
```
