# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

Cosign **v3.0.2** (brew ships 3.1.3, which removes `--tlog-upload=false`, so I pinned 3.0.2 from the releases page). Local registry `registry:3`.

> Environment note: macOS already occupies port **5000** (AirPlay/Control Center returns `403`/garbage there), and Docker 29's containerd image store would not `docker push` to a classic registry ("does not provide any platform"). I therefore ran the registry on **:5055** and loaded it with `crane copy` (same go-containerregistry stack Cosign uses). Commands below use `localhost:5055`.

## Task 1

### The digest I signed, and how I picked it
The image carries two repo digests once it lives in two registries (Docker Hub and the local one); signing the Hub one would send Cosign to a registry I can't push to. I filtered for the local registry:
```
localhost:5055/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

### Successful verify
```
Verification for localhost:5055/juice-shop@sha256:fd58bdc...418b0 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
[{"critical":{"identity":{"docker-reference":"localhost:5055/juice-shop@sha256:fd58bdc...418b0"},
  "image":{"docker-manifest-digest":"sha256:fd58bdc...418b0"},
  "type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

### Swap the image
After overwriting the tag `v20.0.0` with `alpine:3.20`, the tag resolves to a new digest:
```
signed:   localhost:5055/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
now(tag): localhost:5055/juice-shop@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
```
Verifying the **new** (tampered) digest fails, quoted exactly:
```
Error: no signatures found
error during command execution: no signatures found
```
And the **original** digest still verifies afterwards:
```
Verification for localhost:5055/juice-shop@sha256:fd58bdc...418b0 --
  - The cosign claims were validated ...
```

### What the signature is bound to
The signature is bound to the **content digest** — the sha256 of the exact image bytes — not to the human-friendly tag `v20.0.0`. A tag is just a mutable pointer: anyone with push access can repoint `v20.0.0` at a completely different image (here, Alpine), and that is exactly the attack. Because Cosign stores and checks the signature against the digest, the swapped image has *no* signature for its new digest (`no signatures found`), while the bytes I actually signed still verify under their unchanged digest. Had signatures been bound to tags, overwriting the tag would have carried the "valid" mark onto the attacker's image, and verification would have happily passed malware — the whole guarantee would collapse.

## Task 2

### Component counts (must match)
| Source | Components |
|--------|-----------:|
| Lab 4 `juice-shop.cdx.json` | 3068 |
| SBOM extracted from the attestation | 3068 |

### predicateType of each attestation (read from the verified payload)
- CycloneDX SBOM attestation → `https://cyclonedx.org/bom`
- SLSA provenance attestation → `https://slsa.dev/provenance/v0.2`

### Decoded statement fields and their origin (SLSA attestation)
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    { "name": "localhost:5055/juice-shop",
      "digest": { "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0" } }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2"
}
```
- `_type` (`in-toto Statement/v0.1`) — **Cosign filled it in**; it's the fixed in-toto envelope type.
- `subject[].name` + `digest.sha256` — **Cosign filled it in**, derived from the image reference I signed (the registry path and the manifest digest).
- `predicateType` — **Cosign set it from my `--type slsaprovenance` flag**; I supplied the *predicate body* (`/tmp/provenance.json`), and Cosign wrapped it, which is why my file had no `_type`/`subject`.

### Morning after the next Log4Shell
A signature only says "these bytes are unchanged"; the SBOM **attestation says what is inside** each image and is cryptographically bound to its digest. So across 2000 images I can, without pulling or rebuilding anything, verify each attestation and `jq` its component list for the vulnerable `log4j-core` version — turning "which of our images are affected?" from a week of re-scanning into a query. For that to work at 3 a.m., the precondition is that **every image already had a verifiable attestation attached at build time, signed by a key I trust and can reach right now** — if some images were pushed without attestations, or the SBOMs aren't signed (so an attacker could have rewritten them), or I can't get the trusted public key, the attestations are either missing or untrustworthy and I'm back to scanning.

## Bonus

### Verify before and after
Original tarball:
```
Verified OK
```
After the attacker edits `install.sh` and rebuilds the tarball **without re-signing**:
```
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### The two files a consumer needs
1. the **artifact** itself (`my-tool.tar.gz`), and
2. the **signature bundle** (`my-tool.tar.gz.bundle`).

The bundle **may travel over the same channel as the artifact** (same CDN/release page) — tampering with either one breaks verification, so co-locating them is safe. What must **not** be fetched from that same channel is the **public key**: if the attacker who controls the CDN can also hand you the key, they swap artifact + bundle + key together and verification "passes." The key has to arrive out-of-band from a trusted source.

### Install instructions I would publish
```
# 1. Get our public key ONCE, out of band, and pin it (do not re-fetch from the download CDN):
#    published in our signed release notes / key server; fingerprint: <pin here>
# 2. Download the artifact and its bundle:
curl -LO https://dl.example.com/my-tool.tar.gz
curl -LO https://dl.example.com/my-tool.tar.gz.bundle
# 3. VERIFY before running anything:
cosign verify-blob --key my-tool.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz
# 4. Only if it prints "Verified OK", extract and run.
```
Codecov's uploader was signed by nobody and verified by nobody, so a CDN swap went unnoticed. The step most projects skip is **step 3 — actually verifying** (and, underneath it, publishing + pinning the public key through a trusted channel): they may sign, but they never tell users to verify, so `curl | bash` runs whatever the CDN serves.
