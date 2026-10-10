# Lab 8 Submission — Supply Chain: Signing, Tampering, and Attestation

**Git identity:** `shnupel <ufamail.com2@gmail.com>`  
**Cosign:** `v3.0.2`  
**Registry:** local Docker Registry 3 at `127.0.0.1:5000`

The Docker registry was also published as `localhost:5000`. On this macOS host, `localhost:5000` is intercepted by the AirTunes service for direct HTTP requests, so Cosign commands used the equivalent Docker host address `127.0.0.1:5000`.

## Task 1

### Signed digest

I pulled and pushed the Juice Shop image as follows:

```bash
docker pull bkimminich/juice-shop:v20.0.0
docker tag bkimminich/juice-shop:v20.0.0 localhost:5000/juice-shop:v20.0.0
docker push localhost:5000/juice-shop:v20.0.0
```

The image carried these repository digests:

```text
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

I selected the line beginning with `localhost:5000/`, as required by the lab. Docker pushed the available single-platform OCI manifest and reported the registry manifest digest as:

```text
sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

The registry's `Docker-Content-Digest` for the pushed tag confirmed that this was the immutable artifact available to Cosign. I signed:

```text
localhost:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

The difference between the `docker inspect` repository digest and the registry manifest digest occurred because Docker reported the source multi-platform image digest while the local push contained the available single-platform OCI manifest. Cosign must sign the digest that the local registry serves.

I used Cosign 3.0.2 with transparency-log upload disabled for this local-only registry:

```bash
COSIGN_PASSWORD="<local passphrase>" cosign sign \
  --key labs/lab8/keys/cosign.key --tlog-upload=false \
  --allow-insecure-registry --yes \
  127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

The private key was not staged. Git reported:

```text
The following paths are ignored by one of your .gitignore files:
labs/lab8/keys/cosign.key
hint: Use -f if you really want to add them.
```

Verification of the original digest succeeded:

```text
Verification for 127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

The verified signature record contained:

```json
{
  "docker-manifest-digest": "sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113",
  "type": "https://sigstore.dev/cosign/sign/v1"
}
```

### Tag overwrite and verification failure

I overwrote the same tag with Alpine:

```bash
docker pull alpine:3.20
docker tag alpine:3.20 localhost:5000/juice-shop:v20.0.0
docker push localhost:5000/juice-shop:v20.0.0
```

The digest comparison was:

```text
signed:  localhost:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
now:     localhost:5000/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
```

Verification of the swapped image failed with the exact Cosign error:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

The original digest still verified after the tag overwrite. This shows that the signature is bound to the image manifest digest, which identifies the exact content. A tag is a mutable name and can be moved to another manifest. If the signature were bound to the tag, an attacker could overwrite `v20.0.0` and make the old signature appear to approve the new image; digest binding prevents that substitution.

## Task 2

### CycloneDX SBOM attestation

I attached the Lab 4 CycloneDX SBOM to the signed image digest and verified it with:

```bash
COSIGN_PASSWORD="<local passphrase>" cosign attest \
  --key labs/lab8/keys/cosign.key --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json \
  --tlog-upload=false --allow-insecure-registry --yes \
  127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113

cosign verify-attestation --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry --type cyclonedx \
  127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

The component counts matched:

| Source | Component count |
|---|---:|
| `labs/lab4/juice-shop.cdx.json` | 3068 |
| Decoded verified attestation | 3068 |

The verified SBOM statement contained:

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
  "predicateType": "https://cyclonedx.org/bom"
}
```

The `predicateType` was read from the decoded verified payload: `https://cyclonedx.org/bom`.

### SLSA provenance attestation

I created this provenance predicate:

```json
{
  "builder": { "id": "https://localhost/lab8-student" },
  "buildType": "https://example.com/lab8/local-build",
  "invocation": {
    "configSource": {
      "uri": "https://github.com/Shnupel/DevSecOps-Intro"
    }
  }
}
```

I attached and verified it as a SLSA provenance attestation:

```bash
COSIGN_PASSWORD="<local passphrase>" cosign attest \
  --key labs/lab8/keys/cosign.key --type slsaprovenance \
  --predicate /tmp/provenance.json \
  --tlog-upload=false --allow-insecure-registry --yes \
  127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113

cosign verify-attestation --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry --type slsaprovenance \
  127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

The second verified payload reported:

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
    "builder": {
      "id": "https://localhost/lab8-student"
    },
    "buildType": "https://example.com/lab8/local-build",
    "invocation": {
      "configSource": {
        "uri": "https://github.com/Shnupel/DevSecOps-Intro"
      }
    }
  }
}
```

The provenance `predicateType` was read from the decoded verified payload: `https://slsa.dev/provenance/v0.2`.

Cosign filled the in-toto envelope fields `_type`, `subject`, and `predicateType`. The `_type` is the in-toto statement type. The `subject` identifies the image name and digest that I supplied as the Cosign target. The `predicateType` is the type selected by `--type cyclonedx` or `--type slsaprovenance`. I supplied the SBOM predicate body from Lab 4 and the provenance predicate body from `/tmp/provenance.json`.

The morning after the next Log4Shell, the attestation lets an incident responder query the registry for images whose signed SBOM contains the affected component or version, then prioritize those images for isolation and rebuild. A signature alone proves that the image bytes are unchanged after signing, but it does not describe the packages inside the image or how it was built. This works at three in the morning only when every image has a verified attestation, the predicate format is queryable, the registry retains the attestations, and the responder trusts the public key used to verify them.

## Bonus

### Blob signing and tampering

I created and signed a release archive:

```bash
printf '#!/bin/bash\necho "installing my-tool"\n' > /tmp/install.sh
tar -czf labs/lab8/results/my-tool.tar.gz -C /tmp install.sh

COSIGN_PASSWORD="<local passphrase>" cosign sign-blob \
  --key labs/lab8/keys/cosign.key --yes --tlog-upload=false \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle \
  labs/lab8/results/my-tool.tar.gz
```

Verification of the original archive returned:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

I then changed `/tmp/install.sh`, rebuilt the archive without signing it again, and verified it with the original bundle. The exact failure was:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

A consumer needs these two artifact files:

1. `my-tool.tar.gz` — the release artifact.
2. `my-tool.tar.gz.bundle` — the Cosign signature bundle.

The bundle may travel over the same channel as the archive because it verifies the archive's content. The public key is a separate trust anchor and must be distributed or pinned through a trusted channel; downloading the public key only from the same untrusted location would not establish who signed the release.

For a safe installation, I would publish the archive, its Cosign bundle, and the public key fingerprint through separate trusted channels. The installation instructions would download the archive and bundle, obtain the pinned public key from a trusted repository or preinstalled package, run `cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz`, and extract or execute the archive only after the command returns `Verified OK`. The key step most projects skip is verification before execution: Codecov's modified uploader was run by thousands of pipelines without an independent signature check.
