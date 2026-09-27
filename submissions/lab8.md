# Lab 8 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (sign + tag swap) · Task 2 (CycloneDX + SLSA attestations) · **Bonus Task** (`cosign sign-blob`, +2 pts)

I signed Juice Shop in a local registry, overwrote the tag with Alpine, and showed which digest still verifies. I attached and verified CycloneDX and SLSA attestations, then repeated the tamper test with `cosign sign-blob`. Submitted files: this report and [`labs/lab8/keys/cosign.pub`](../labs/lab8/keys/cosign.pub). Private key, registry state, and raw outputs stay local / gitignored.

## Environment and reproducibility

| Item | Value |
|------|-------|
| Run date | 27 September 2026 |
| Host | macOS (darwin/arm64) |
| Cosign | **v3.0.2** (`~/.local/bin/cosign-3.0.2`; brew’s 3.1.x breaks `--tlog-upload=false`) |
| Registry | `registry:3`, published as `-p 127.0.0.1:5000:5000` |
| Image | Juice Shop v20.0.0 |
| SBOM input | Lab 4 CycloneDX (`labs/lab4/juice-shop.cdx.json`), **3068** components |

**Why `127.0.0.1` instead of the brief’s `localhost` hostname:** on this Mac, `localhost` resolves to `::1` first, and AirPlay Receiver already listens on `*:5000`. Cosign then hits AirPlay (HTTP 403 / TLS timeout) instead of the registry. Binding and addressing the registry as `127.0.0.1:5000` is the same plain-HTTP local registry the lab intends; only the hostname string differs. Passphrase via `COSIGN_PASSWORD` in the environment — never committed.

## Task 1

### Publish and select the digest

```bash
docker run -d --name lab8-registry -p 127.0.0.1:5000:5000 registry:3
docker tag bkimminich/juice-shop:v20.0.0 127.0.0.1:5000/juice-shop:v20.0.0
docker push 127.0.0.1:5000/juice-shop:v20.0.0
docker pull 127.0.0.1:5000/juice-shop:v20.0.0   # refreshes RepoDigests to the local registry
docker inspect 127.0.0.1:5000/juice-shop:v20.0.0 \
  --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep '^127.0.0.1:5000/'
```

Signed reference:

```text
127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

How it was chosen: filter `RepoDigests` for the **local registry** prefix (never assume index `0` — that can still be Docker Hub). Push also reported `digest: sha256:cbdfc00…`, and `Docker-Content-Digest` on `GET /v2/juice-shop/manifests/v20.0.0` matched. Docker noted the Hub multi-arch index `sha256:fd58…` mapped to this single-platform local manifest `sha256:cbdfc00…` — same app build, index vs child manifest, not two different applications. Signing `fd58…` against the local registry returns 404.

### Key pair and private-key refusal

```bash
cd labs/lab8/keys && cosign generate-key-pair && cd -
git add labs/lab8/keys/cosign.key
```

```text
The following paths are ignored by one of your .gitignore files:
labs/lab8/keys/cosign.key
hint: Use -f if you really want to add them.
```

Did not use `-f`. Only `cosign.pub` is in the PR.

### Sign and verify

```bash
COSIGN_PASSWORD=… cosign sign \
  --key labs/lab8/keys/cosign.key --tlog-upload=false \
  --allow-insecure-registry --yes "$DIGEST"

cosign verify --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry "$DIGEST"
```

Exit code **0**. Successful verify output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.

Verification for 127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

### Tag overwrite (tamper)

```bash
docker pull alpine:3.20
docker tag alpine:3.20 127.0.0.1:5000/juice-shop:v20.0.0
docker push 127.0.0.1:5000/juice-shop:v20.0.0
docker pull 127.0.0.1:5000/juice-shop:v20.0.0
```

Tag now resolves to:

```text
127.0.0.1:5000/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
```

Verify on the **new** digest — exit **10**, exact error:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

Verify on the **original** `$DIGEST` afterwards — still exit **0** with the same successful JSON as above (tag was not restored).

### What the signature is bound to

The signature authenticates the **manifest digest** (and records the repository identity), not the mutable string `v20.0.0`. Moving the tag to Alpine changes which digest the name selects; Alpine has no signature under our key (`no signatures found`). The original digest still verifies because its bytes and signature were untouched. If signatures were bound only to tags, an attacker could retarget the same tag at different content and keep a “valid” approval — exactly what this demo prevents.

## Task 2

### CycloneDX attestation

Attached Lab 4’s SBOM to the **original** Juice Shop digest (while the tag still pointed at Alpine):

```bash
COSIGN_PASSWORD=… cosign attest \
  --key labs/lab8/keys/cosign.key --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json \
  --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"

cosign verify-attestation --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry --type cyclonedx "$DIGEST" \
  | jq -r '.payload | @base64d | fromjson | .predicate' \
  > labs/lab8/results/sbom-from-attestation.json
```

| Check | Value |
|-------|------:|
| Lab 4 `.components \| length` | **3068** |
| Extracted attestation predicate | **3068** |

### SLSA provenance attestation

Predicate body supplied (no `_type` / `subject` — Cosign wraps them):

```json
{
  "builder": { "id": "https://localhost/lab8-student" },
  "buildType": "https://example.com/lab8/local-build",
  "invocation": { "configSource": { "uri": "https://github.com/An11y/DevSecOps-Intro" } }
}
```

```bash
cosign attest --type slsaprovenance --predicate … "$DIGEST"
cosign verify-attestation --type slsaprovenance "$DIGEST" \
  | jq -r '.payload | @base64d | fromjson | .predicateType'
```

Both attestations verify (exit 0) with both present.

### `predicateType` values (from verified payloads)

| Attestation | `predicateType` |
|-------------|-----------------|
| CycloneDX | `https://cyclonedx.org/bom` |
| SLSA provenance | `https://slsa.dev/provenance/v0.2` |

### Statement fields and origin

CycloneDX statement (from verified payload):

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

SLSA statement: same `_type` / `subject`, `predicateType` = `https://slsa.dev/provenance/v0.2`.

| Field | Origin |
|-------|--------|
| `predicate` | I supplied (SBOM file / three-field provenance JSON) |
| `_type` | Cosign’s in-toto Statement wrapper |
| `subject` | Cosign, from the digest-qualified reference I attested |
| `predicateType` | Cosign maps `--type cyclonedx` / `slsaprovenance` to these URIs |

### Morning after Log4Shell

A signature answers “are these the same bytes I signed?” An SBOM attestation answers “which packages are inside?” — so two thousand images can be queried for a vulnerable package/version without re-scanning every layer. Preconditions at 03:00: attestations exist and are searchable, signatures verify under keys we trust, subjects match the digests actually deployed, and the SBOMs actually cover those runtimes. Missing or unsigned inventories put those images back on the slow path. A valid signature alone does not inventory packages.

## Bonus

### Sign a blob, then change it

```bash
printf '#!/bin/bash\necho "installing my-tool"\n' > /tmp/install.sh
tar -czf labs/lab8/results/my-tool.tar.gz -C /tmp install.sh

COSIGN_PASSWORD=… cosign sign-blob \
  --key labs/lab8/keys/cosign.key --yes --tlog-upload=false \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle \
  labs/lab8/results/my-tool.tar.gz

cosign verify-blob --key labs/lab8/keys/cosign.pub \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle --insecure-ignore-tlog \
  labs/lab8/results/my-tool.tar.gz
```

Exact verify output on the original:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

Changed the script to `echo "modified installer for the tamper test"`, rebuilt the tarball at the same path **without** re-signing:

| Archive | SHA-256 |
|---------|---------|
| Original | `96101c4b1f9337fc039864db858bfffd362cefb85faf0b287d9bd9311dc0e07e` |
| Modified | `2aa15ca441b0369ec2f86cc11f01f2491e6d7abe5df100125fe50d310ab9d5e6` |

Exact error on the modified archive:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### What a consumer needs

Beyond the artifact: **`my-tool.tar.gz.bundle`** and a **trusted `cosign.pub`**. The bundle may share the CDN with the artifact (changing either breaks verification under a pinned key). The public key must arrive through an **independent, authenticated** channel or be pinned in config — downloading a replacement key from the same compromised CDN defeats the check. That is the key-distribution problem.

### Install instructions (Codecov-style failure prevented)

```bash
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
release='https://downloads.example.com/my-tool/v1.0.0'
curl --fail --silent --show-error --location "$release/my-tool.tar.gz" -o my-tool.tar.gz
curl --fail --silent --show-error --location "$release/my-tool.tar.gz.bundle" -o my-tool.tar.gz.bundle
# cosign.pub already provisioned out-of-band — not fetched from that CDN
cosign verify-blob --key /etc/my-tool/trusted/cosign.pub \
  --bundle my-tool.tar.gz.bundle --insecure-ignore-tlog my-tool.tar.gz
tar -xzf my-tool.tar.gz
bash ./install.sh
```

Download first; verify; only then extract/run. The step most projects skip is **pinning a trust root and verifying before execute** (`curl | bash` never checks a signature).

## Final checks and cleanup

- Original digest verified before and after the tag swap.
- Tampered digest: `no signatures found` (exit 10).
- Both attestation types verified; component counts both **3068**.
- Blob: `Verified OK`, then invalid signature after modification.
- Only `submissions/lab8.md` and `labs/lab8/keys/cosign.pub` committed.

Cleanup: `docker rm -f lab8-registry`.
