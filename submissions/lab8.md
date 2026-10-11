# Lab 8 - Submission

Scan snapshot: 2026-07-02, using Cosign v3.1.1, Docker 29.2.1, Syft 1.45.1, and jq 1.7.1. I used `127.0.0.1:5000` for the local registry reference; it is the same loopback registry as `localhost:5000`, but avoids a Docker Desktop localhost/proxy quirk during registry inspection.

## Task 1: Sign + Tamper Demo

### Registry + image push

- Registry container: `lab8-registry` running on `127.0.0.1:5000`
- Image pushed: `127.0.0.1:5000/juice-shop:v20.0.0`
- Image digest: `127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113`

The original Docker Hub image index digest from Lab 4 was `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`. The local registry stored the available arm64 single-platform manifest as `sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113`, and that is the digest I signed.

### Signing

Output of `cosign sign`:

```text
Signing artifact...
Pushing signature to: 127.0.0.1:5000/juice-shop
```

Cosign v3.1.1 no longer accepts the old `--tlog-upload=false` flow directly, so I used a local signing config without Fulcio/OIDC/Rekor/TSA services for this keyed local-registry lab.

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

Tampered digest:

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

```json
[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters

Cosign signs the immutable image digest, not the mutable tag. The tampered tag pointed to an Alpine manifest with a different digest, so the old Juice Shop signature did not apply and verification failed. If Cosign signed only `:v20.0.0`, an attacker who could move that tag could make a different image look signed even though the bytes changed.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Lab 4 SBOM source: `feature/lab4:labs/lab4/juice-shop.cdx.json`
- Component count matches Lab 4 source: yes, `3068`
- diff between Lab 4 SBOM component count and extracted SBOM component count: empty output

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
    "components": [
      { "type": "library", "name": "1to2", "version": "1.0.0" },
      { "type": "library", "name": "@adraffy/ens-normalize", "version": "1.10.1" },
      { "type": "library", "name": "@ai-sdk/gateway", "version": "3.0.114" }
    ]
  }
}
```

### Provenance attestation

- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-wyroxx`
- buildType in predicate: `https://example.com/lab8/local-registry-signing`

Decoded provenance payload:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "buildType": "https://example.com/lab8/local-registry-signing",
    "builder": {
      "id": "https://localhost/lab8-wyroxx"
    },
    "invocation": {
      "configSource": {
        "digest": {
          "sha1": "17af20d"
        },
        "uri": "https://github.com/wyroxx/DevSecOps-Intro.git"
      }
    }
  }
}
```

### What this gives a Lab 9 verifier

A signed image proves who authorized a specific digest, but it does not say what components are inside it. A signed image with an SBOM attestation lets an admission-time verifier or response workflow prove that the deployed digest has inventory attached; when the next Log4Shell-style event happens, the team can query the attested components instead of rediscovering what every image contains under pressure.

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

The Codecov attack worked because consumers downloaded a shell uploader and executed it without verifying that the bytes matched a trusted release. If CI had run `cosign verify-blob --key cosign.pub --bundle uploader.bundle uploader.sh` before execution, the attacker-modified byte stream would not have matched the signed bundle and the pipeline could stop before running the malicious script. That does not make `curl | bash` a good pattern, but it turns unauthenticated script execution into a verifiable release artifact workflow.
