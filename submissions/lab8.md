# Lab 8 — Submission

## Environment

- Docker: 29.2.0
- Cosign: v3.1.1
- jq: 1.7.1
- Registry: `lab8-registry` on `127.0.0.1:5000`

Note: on this macOS host, `localhost:5000` resolved to an Apple AirTunes listener on IPv6 and returned `403 Forbidden`. I used `127.0.0.1:5000` for the local registry and Cosign commands.

## Task 1: Sign + Tamper Demo

### Registry + image push

- Registry container: `lab8-registry` running on `127.0.0.1:5000`
- Image pushed: `127.0.0.1:5000/juice-shop:v20.0.0`
- Image digest:

```text
127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

### Signing

Output of `cosign sign`:

```text
Signing: 127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
Signing artifact...
Pushing signature to: 127.0.0.1:5000/juice-shop
```

Cosign v3.1.1 no longer accepts `--tlog-upload=false` directly with the default signing config, so I used a local signing config with no Rekor/TSA services for this local registry exercise:

```json
{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json","rekorTlogConfig":{},"tsaConfig":{}}
```

### Verification (PASSED)

Output of `cosign verify` on original digest:

```json
[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demo (FAILED — correctly)

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

### Sanity — original still verifies

```json
[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters

The tampered re-tag pointed to a different digest (`sha256:45e099...`) while the signature was bound to the original digest (`sha256:cbdfc...`). If Cosign signed only the mutable tag, an attacker could replace the tag target with another image and still appear to have a valid signature. Digest binding prevents that tag-mutation attack because verification is tied to immutable image content.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Component count matches Lab 4 source: yes
- Lab 4 component count: `905`
- Extracted attestation component count: `905`
- diff between Lab 4 SBOM and extracted-from-attestation component count: empty output

Decoded attestation payload summary:

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
    "specVersion": "1.7",
    "componentCount": 905
  }
}
```

### Provenance attestation

- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

Decoded provenance payload:

```json
{
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "buildType": "https://example.com/lab8/local-build",
    "builder": {
      "id": "https://localhost/lab8-student"
    },
    "invocation": {
      "configSource": {
        "digest": {
          "sha1": "34cdac3"
        },
        "uri": "https://github.com/0xsmk/DevSecOps-Intro"
      }
    }
  }
}
```

### What this gives a Lab 9 verifier

A signed image proves who signed a specific digest, but it does not tell the admission controller what is inside the image. A signed image with a CycloneDX SBOM attestation lets a Kyverno or Sigstore policy-controller rule require both the signature and the presence of inspectable package inventory. When the next Log4Shell-style vulnerability appears, the platform can query or require SBOM evidence at admission time instead of treating all signed images as equally understandable.

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

Codecov's bash uploader attack worked because consumers fetched a script and executed it without verifying that the bytes were the expected release artifact. If consumers had required `cosign verify-blob --key cosign.pub --bundle uploader.bundle uploader.sh` before execution, the modified byte stream would not have matched the signature bundle. The attack would have failed at verification time before the malicious script reached `bash`.
