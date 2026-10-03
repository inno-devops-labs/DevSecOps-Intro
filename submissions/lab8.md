# Lab 8 — Supply Chain Signing

## Task 1

### Digest signed
`127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113`

Picked via the local registry’s `Docker-Content-Digest` after `docker push` (and confirmed with `curl -I` Accept OCI/Docker manifest). Not the Docker Hub digest `sha256:fd58bdc9…` — signing that would talk to Hub, where we cannot push signatures.

### Successful verify
```
Verification for 127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

### Tamper
Overwrote tag `v20.0.0` with `alpine:3.20` → tag now resolves to  
`127.0.0.1:5000/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d`.

```
Error: no signatures found
```

Original digest still verifies afterwards (same successful verify block as above).

### Bound to digest, not tag
The Cosign signature is bound to the **image manifest digest**. Moving the mutable tag `v20.0.0` onto Alpine does not move the signature; Cosign correctly reports no signature on the new digest. If signatures were bound to tags, an attacker could overwrite `v20.0.0` and keep a “valid” tag-level claim — this exact swap would succeed.

Public key committed: `labs/lab8/keys/cosign.pub` (private key never committed). Cosign **v3.0.2**.

## Task 2

### Component counts
| Source | `.components \| length` |
|--------|------------------------:|
| Lab 4 `labs/lab4/juice-shop.cdx.json` | **3068** |
| Extracted attestation predicate | **3068** |

### predicateType values (from verified payloads)
| Attestation | predicateType |
|-------------|---------------|
| CycloneDX | `https://cyclonedx.org/bom` |
| SLSA provenance | `https://slsa.dev/provenance/v0.2` |

### Decoded statement fields (CycloneDX example)
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "127.0.0.1:5000/juice-shop",
      "digest": { "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113" }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom"
}
```
- **We supplied:** the predicate body (CycloneDX SBOM / SLSA provenance JSON) and `--type`.
- **Cosign filled in:** `_type` (in-toto Statement), `subject` (image name + digest being attested), and the wrapping `predicateType` URI for that `--type`.

### Morning after Log4Shell
A signature alone only answers “is this bit-for-bit the artifact I signed?”. The CycloneDX attestation lets you **query which of ~2000 images contain the vulnerable package** without re-pulling and re-scanning every layer — if (and only if) you still trust the signing key, attestations were attached at build/release time, and you can enumerate subjects in the registry. Without those preconditions, you fall back to slow full rescans.

## Bonus

### Verify blob
Original tarball:
```
Verified OK
```
After rewriting `install.sh` and rebuilding the tarball without re-signing:
```
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Two files a consumer needs
1. The artifact (`my-tool.tar.gz`)
2. The Cosign bundle (`my-tool.tar.gz.bundle`) **and** your **public key** (or keyless identity) obtained over a **different trust channel** than the CDN that hosts the tarball. The bundle may travel beside the artifact; the public key must not be solely from the same compromised CDN.

### Codecov-style install instructions
Publish:
```bash
curl -fsSL https://example.com/my-tool.tar.gz -o my-tool.tar.gz
curl -fsSL https://example.com/my-tool.tar.gz.bundle -o my-tool.tar.gz.bundle
cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz
tar -xzf my-tool.tar.gz && ./install.sh
```
Pin/obtain `cosign.pub` from the project’s GitHub release assets or a keyserver — **not** only from the same host as the script. The step most projects skip is **verify-before-execute** (they stop at `curl | bash`).
