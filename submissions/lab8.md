# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113`

### Signing
- Output of `cosign sign`:
  ```
    Pushing signature to: localhost:5000/juice-shop
  ```


### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "localhost:5000/juice-shop:v20.0.0"
      },
      "image": {
        "docker-manifest-digest": "sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "type": "https://sigstore.dev/cosign/sign/v1"
    },
    "optional": {}
  },
  {
    "critical": {
      "identity": {
        "docker-reference": "localhost:5000/juice-shop:v20.0.0"
      },
      "image": {
        "docker-manifest-digest": "sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "type": "https://slsa.dev/provenance/v0.2"
    },
    "optional": {}
  },
  {
    "critical": {
      "identity": {
        "docker-reference": "localhost:5000/juice-shop:v20.0.0"
      },
      "image": {
        "docker-manifest-digest": "sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "type": "https://cyclonedx.org/bom"
    },
    "optional": {}
  },
  {
    "critical": {
      "identity": {
        "docker-reference": "localhost:5000/juice-shop:v20.0.0"
      },
      "image": {
        "docker-manifest-digest": "sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "type": "https://sigstore.dev/cosign/sign/v1"
    },
    "optional": {}
  }
]
```


### Tamper Demo (FAILED — correctly)
Output of  on tampered digest:
```
Error: no matching signatures:
localhost:5000/juice-shop@sha256:... (tampered)
main.go: ...: signature not found
```


### Sanity — original still verifies

Verification for localhost:5000/juice-shop:v20.0.0 --
The following checks were performed on each of these signatures:
- The cosign claims were validated
- Existence of the claims in the transparency log was verified offline
- The signatures were verified against the specified public key


### Why digest binding matters (Lecture 8 slide 6)

The signature is bound to the cryptographic digest of the image manifest, not to a mutable tag. If we had signed the tag `v20.0.0`, an attacker could overwrite that tag with a different image (as demonstrated with the `alpine` re‑tag) and the signature would still be considered valid because verification would only check the tag. Binding to the digest ensures that any substituted image—even with the same tag—will be rejected because its digest does not match the signed one.---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (fragment with `cyclonedx` type):
```
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "digest": {
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "annotations": {}
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    ... (truncated for brevity)
  }
}
```
- Component count matches Lab 4 source: **yes** (empty diff)
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM:
```
  (empty)
```

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`
- Verification output:
  ```
  {
  "critical": {
    "identity": {
      "docker-reference": "localhost:5000/juice-shop:v20.0.0"
    },
    "image": {
      "docker-manifest-digest": "sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
    },
    "type": "https://slsa.dev/provenance/v0.2"
  },
  "optional": {}
  }
  ```

### What this gives a Lab 9 verifier (2-3 sentences)

Having an SBOM attestation allows a policy engine (e.g., Kyverno) at admission time to not only verify the image's integrity but also check that known vulnerabilities (like Log4Shell) are absent from its dependencies before the image is admitted into the cluster. A signed SBOM guarantees that the component list was not tampered with after the build, and provenance confirms the image's origin—both critical when responding to new vulnerabilities, as we can quickly identify which images are affected even if they were built long ago.

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
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)
The Codecov bash uploader was distributed via `curl | bash` without signature verification. If consumers had verified the script with `cosign verify-blob --key <pubkey> --bundle <bundle> script.sh` before executing it, the compromised script would have been rejected because its hash would not match the signed one. This is exactly the same pattern we applied with `sign-blob` to our own artifact.