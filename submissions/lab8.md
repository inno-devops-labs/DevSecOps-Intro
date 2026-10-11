# Lab 8 - Submission

## Task 1: Sign + Tamper Demo

### Registry + image push

- Registry container: `lab8-registry` running on `127.0.0.1:5000`
- Image pushed: `127.0.0.1:5000/juice-shop:v20.0.0`
- Image digest:

```text
127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

Note: I used `127.0.0.1` instead of `localhost` because macOS resolved `localhost` to IPv6 `::1`, where another local service returned `403`. The registry itself was healthy on IPv4.

### Signing

Cosign version: `v3.1.1`.

Cosign v3 no longer accepts the old `--tlog-upload=false` flow directly, so I used a local signing config without Rekor/TSA services:

```bash
cosign signing-config create \
  --no-default-rekor \
  --no-default-tsa \
  --out labs/lab8/results/signing-config-no-tlog.json
```

Output of `cosign sign`:

```text
Signing: 127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
Signing artifact...
Pushing signature to: 127.0.0.1:5000/juice-shop
```

### Verification (PASSED)

Output of `cosign verify` on original digest:

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
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

### Tamper Demo (FAILED - correctly)

Tampered image digest:

```text
127.0.0.1:5000/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
```

Output of `cosign verify` on tampered digest:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity - original still verifies

```text
Verification for 127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

### Why digest binding matters (Lecture 8 slide 6)

The signature was attached to the original manifest digest, not to the mutable tag name. When `alpine:3.20` was pushed under a similar `juice-shop` tag, it resolved to a different digest and Cosign correctly found no matching signature. If Cosign signed tags instead of digests, an attacker could reuse a trusted tag name while changing the underlying bytes.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Component count matches Lab 4 source: yes (`3068`)
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM component count: empty output

Verify-attestation decoded payload excerpt:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "127.0.0.1:5000/juice-shop",
      "digest": {
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "componentCount": 3068,
    "firstComponent": {
      "name": "1to2",
      "type": "library",
      "version": "1.0.0",
      "purl": "pkg:npm/1to2@1.0.0"
    },
    "metadataComponent": {
      "name": "bkimminich/juice-shop",
      "type": "container",
      "version": "v20.0.0"
    }
  }
}
```

### Provenance attestation

- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

Decoded provenance predicate:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "127.0.0.1:5000/juice-shop",
      "digest": {
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "buildType": "https://example.com/lab8/local-build",
    "builder": {
      "id": "https://localhost/lab8-student"
    },
    "invocation": {
      "configSource": {
        "digest": {
          "sha1": "abc123"
        },
        "uri": "https://github.com/JoraXD/DevSecOps-Intro"
      }
    }
  }
}
```

### What this gives a Lab 9 verifier

At admission time, a verifier can require both a valid image signature and an SBOM attestation for the exact digest. A signed image without an SBOM only proves who approved those bytes; it does not provide an inventory for fast impact analysis when the next Log4Shell-style dependency issue appears. A signed image with an SBOM lets policy and vulnerability management answer "does this exact deployed digest contain the affected component?" without rebuilding or rescanning from scratch.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify

- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`

Verify-blob success output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation

The Codecov bash uploader attack worked because consumers downloaded and executed a script without verifying that the bytes came from the publisher. If consumers had required `cosign verify-blob --key cosign.pub --bundle uploader.bundle uploader.sh` before running the script, the attacker-modified byte stream would not have matched the signature bundle and CI would have failed before execution. The same pattern is shown here: appending `MALICIOUS PAYLOAD` made verification fail with an invalid signature.
