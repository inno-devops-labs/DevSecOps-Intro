# Lab 8 - Submission

## Task 1: Sign + Tamper Demo

### Tool versions

```text
cosign v2.4.3
Docker 29.5.3
registry:3
jq 1.7.1
```

### Registry + image push

- Registry container: `lab8-registry` running on `127.0.0.1:5000`
- Image pushed: `127.0.0.1:5000/juice-shop:v20.0.0`
- Image digest: `127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113`

Note: on this macOS host, `localhost:5000` resolved to `::1:5000`, where AirTunes returned `403`. The registry was bound to IPv4, so the lab commands used `127.0.0.1:5000`.

### Signing

```text
Pushing signature to: 127.0.0.1:5000/juice-shop
tlog entry created with index: 2047720100
```

### Verification (PASSED)

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "127.0.0.1:5000/juice-shop"
      },
      "image": {
        "docker-manifest-digest": "sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "type": "cosign container image signature"
    }
  }
]
```

### Tamper Demo (FAILED - correctly)

Tampered digest:

```text
127.0.0.1:5000/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
```

Verification output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity - original still verifies

```text
Verification for 127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

### Why digest binding matters

The tampered tag pointed at a different manifest digest, so the original signature did not apply and verification returned `no signatures found`. If Cosign signed mutable tags instead of immutable digests, an attacker could move `:v20.0.0` to a different image and still appear to satisfy a tag-based policy. Digest binding makes the signed object content-addressed.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Component count in Lab 4 source SBOM: `3069`
- Component count extracted from attestation: `3069`
- Diff between counts: empty diff

Decoded payload summary:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "127.0.0.1:5000/juice-shop",
      "digest": {
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      }
    }
  ],
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": 3069
  }
}
```

### Provenance attestation

- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-walkerino`
- buildType in predicate: `https://example.com/lab8/local-registry-signing`

Decoded predicate:

```json
{
  "builder": {
    "id": "https://localhost/lab8-walkerino"
  },
  "buildType": "https://example.com/lab8/local-registry-signing",
  "invocation": {
    "configSource": {
      "uri": "https://github.com/Walkerino/DevSecOps-Intro",
      "digest": {
        "sha1": "523678d"
      }
    }
  }
}
```

### What this gives a Lab 9 verifier

A signed image without an SBOM only proves who signed that digest; it does not give admission control enough inventory to answer "does this contain vulnerable package X?" When the next Log4Shell-style issue appears, a signed SBOM attestation lets a verifier or incident responder connect the running image digest to a component inventory and make policy decisions without rebuilding the image.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify

- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Error: invalid signature when validating ASN.1 encoded signature
error during command execution: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation

Codecov's bash uploader attack worked because consumers downloaded and executed a mutable script without verifying an authentic signature. If CI had required `cosign verify-blob --key cosign.pub --bundle uploader.bundle uploader.sh` before execution, the modified byte stream would not have matched the signed bundle and the pipeline would have failed before `bash` ran the payload.
