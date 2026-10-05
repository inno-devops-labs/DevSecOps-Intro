# Lab 8 — Submission

Supply-chain signing with Cosign: sign the Juice Shop image in a local registry, prove a swapped
image fails verification, then (Tasks 2+) attest the SBOM and sign a release artifact.

## Setup

```console
$ cosign version | grep GitVersion
GitVersion:    v3.0.1
$ docker --version
Docker version 28.0.1
```

**Version note:** the lab says "Cosign 3.0.x, not 3.1.x", but that pin is too loose — **v3.0.6
already removed working `--tlog-upload=false`** (it errors with "not supported with
--signing-config"). I pinned **v3.0.1**, the newest release where every command in this lab still
works. The usable range is roughly v3.0.1–v3.0.3.

## Task 1 — Sign an image, then try to swap it

### 8.1 Registry and the digest I signed

A local registry (`registry:3` on `127.0.0.1:5000`), with Juice Shop pulled, re-tagged and pushed
to it. The image carries **two** repo digests — one for Docker Hub, one for the local registry —
so I selected the local one explicitly:

```console
$ docker inspect localhost:5000/juice-shop:v20.0.0 \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep '^localhost:5000/'
localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d
```

Picking the `localhost:5000/...` digest matters: `{{index .RepoDigests 0}}` can return the Docker
Hub digest, and signing that sends Cosign to Docker Hub, where I can't push.

### 8.2 Key and signature over the digest

`cosign generate-key-pair` created `labs/lab8/keys/cosign.{key,pub}`. The private key is refused
by **two** independent guards — I tried to commit it and watched:

```console
$ git add labs/lab8/keys/cosign.key
The following paths are ignored by one of your .gitignore files:
labs/lab8/keys/cosign.key          # layer 1: *.key is gitignored

$ git add -f labs/lab8/keys/cosign.key && git commit -m "test"
Detect hardcoded secrets.................................................Failed    # layer 2: gitleaks
- hook id: gitleaks
- exit code: 1
```

Signed the digest off the public transparency log (a registry on my laptop has no business in
Rekor):

```console
$ COSIGN_PASSWORD=… cosign sign --key labs/lab8/keys/cosign.key \
    --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"
```

Verification succeeded (`labs/lab8/results/verify-original.json`):

```
Verification for localhost:5000/juice-shop@sha256:8c76bce9…3c0d --
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:8c76bce9…3c0d"},
  "image":{"docker-manifest-digest":"sha256:8c76bce9…3c0d"},
  "type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

### 8.3 Swap the image

Pushed `alpine:3.20` onto the same `v20.0.0` tag — same name, different image:

```
signed:  localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d
now:     localhost:5000/juice-shop@sha256:6c2a9711b0a9f32b0239d9222eb1072309cf46c6431d319ae249186d811a987c
```

Verifying the tag's new digest **fails** (`labs/lab8/results/verify-tampered.txt`):

```
Error: no signatures found
error during command execution: no signatures found
```

And the digest I actually signed **still verifies** afterwards:

```console
$ cosign verify --key cosign.pub --insecure-ignore-tlog --allow-insecure-registry \
    localhost:5000/juice-shop@sha256:8c76bce9…3c0d
{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"}
```

### What the signature is bound to

Cosign signed the image's **content digest** — the SHA-256 of the image manifest — not the tag
`v20.0.0`. A tag is just a mutable label that points at whatever digest was last pushed; the
signature is stored under, and verified against, the immutable digest. When I overwrote the tag
with Alpine, the tag resolved to a brand-new digest that nothing had ever signed, so verification
found no signature and failed — exactly as it should. **Had signatures been bound to tags instead,
the swap would have passed silently:** `v20.0.0` would still carry a "valid" signature while
serving a completely different image, which is the supply-chain attack the whole exercise is
about. Binding to the digest is what makes the signature a statement about *these exact bytes*, not
about a name someone else can repoint.

## Task 2 — Attach the SBOM as an attestation

Two attestations attached to the same signed digest: the Lab 4 CycloneDX SBOM, and a
hand-written SLSA provenance predicate.

### Component counts match

The SBOM round-trips through the attestation unchanged:

```console
$ jq '.components | length' labs/lab4/juice-shop.cdx.json          # source SBOM
3069
$ jq '.components | length' labs/lab8/results/sbom-from-attestation.json   # pulled back out
3069
```

The second number comes from decoding the verified attestation payload
(`.payload | @base64d | fromjson | .predicate`), not from the original file — so 3069 = 3069
proves the SBOM I signed is byte-for-byte what verification returns.

### predicateType of each attestation

Read out of each verified payload:

| Attestation | `predicateType` |
|---|---|
| `--type cyclonedx` | `https://cyclonedx.org/bom` |
| `--type slsaprovenance` | `https://slsa.dev/provenance/v0.2` |

### The decoded statement, and who supplied each field

The SLSA attestation's in-toto statement:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [{ "name": "localhost:5000/juice-shop",
                "digest": { "sha256": "8c76bce9…3c0d" } }],
  "predicate": { "builder": { "id": "https://localhost/lab8-student" },
                 "buildType": "https://example.com/lab8/local-build",
                 "invocation": { "configSource": { "uri": "https://github.com/karam13549/DevSecOps-Intro" } } }
}
```

- **`_type`** — Cosign filled it in; it's the in-toto Statement wrapper, the same for every
  attestation regardless of type.
- **`subject`** — Cosign filled it in, derived from the image digest I pointed `attest` at (name +
  sha256). This is what binds the statement to *this* image.
- **`predicateType`** — Cosign set it from my `--type slsaprovenance` flag (it maps the short name
  to the SLSA URI; `--type cyclonedx` maps to `cyclonedx.org/bom`).
- **`predicate`** — entirely mine: the exact JSON body I passed with `--predicate`. This is why the
  SLSA file on disk has no `_type` or `subject` — Cosign wraps the predicate in the statement for
  me (`--type slsaprovenance` expects the body only).

### The morning after the next Log4Shell

A signature only tells me an image is the unchanged thing I signed — it says nothing about what's
*inside* it. The signed SBOM attestation does: with 2000 images each carrying one, I can pull and
verify each attestation and query its component list for `log4j` (or `lodash`, or whatever just
broke) and get the exact affected images and versions in minutes, without rebuilding or re-scanning
a single one. For that to actually work at three in the morning, several things have to already be
true: every image needs an attestation (coverage — the one image without one is the one that bites
you), the SBOMs must have been generated accurately at build time and bound to the digest that's
really running, I must hold and trust the public key(s) that signed them, and I need tooling to
verify and query 2000 attestations at scale rather than by hand. The attestation turns an incident
from "rebuild and rescan everything and hope" into "run a query against signed evidence I already
have."

## Bonus — Sign the thing people curl

`cosign sign-blob` over a release tarball — the step missing from Codecov's `curl | bash`.

```console
$ cosign sign-blob --key cosign.key --yes --tlog-upload=false \
    --bundle my-tool.tar.gz.bundle my-tool.tar.gz
$ cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle \
    --insecure-ignore-tlog my-tool.tar.gz
Verified OK
```

Then the attacker edits the script (injects `curl … | bash`), rebuilds the tarball **without
re-signing**, and verification rejects it (`labs/lab8/results/verify-blob-tampered.txt`):

```
Error: failed to verify signature: could not verify message:
invalid signature when validating ASN.1 encoded signature
```

### The two files a consumer needs

Besides the artifact itself, a consumer needs the **signature bundle**
(`my-tool.tar.gz.bundle`) and the **public key** (`cosign.pub`). The **bundle may travel over the
same channel as the artifact** — a download server, a CDN, the same release page — because it is
worthless to an attacker without the private key: tamper with the tarball and the bundle no longer
matches. The **public key must not**: it has to reach the user over a separate, trusted channel,
because an attacker who controls the artifact's channel would otherwise swap the key to match their
modified tarball, and the verification would "pass".

### Install instructions that can't be poisoned

> 1. Get our public key once, from a channel we don't serve the binary from — e.g. our HTTPS docs
>    site or a pinned value in your repo: `COSIGN_KEY=https://acme.example/keys/cosign.pub`.
> 2. Download both the artifact and its `.bundle`.
> 3. `cosign verify-blob --key "$COSIGN_KEY" --bundle my-tool.tar.gz.bundle my-tool.tar.gz`
> 4. Only if that prints `Verified OK`, extract and run it. **Never** `curl … | bash`.

The point is that step 3 runs *before* anything executes, and the key in step 1 comes from
somewhere the artifact's server can't rewrite. The step most projects skip is exactly that
out-of-band key distribution plus a mandatory verify: the common pattern publishes a SHA-256
checksum *on the same page as the download*, so a CDN compromise (Codecov) swaps the binary and the
checksum together and the user verifies a tampered file against a tampered hash. A signature only
helps if the key is pinned somewhere the attacker doesn't control.

## Artifacts

- `labs/lab8/keys/cosign.pub` — public key (committed deliverable).
- `labs/lab8/results/verify-original.json` — successful image verification.
- `labs/lab8/results/verify-tampered.txt` — the swapped-image failure.
- `labs/lab8/results/sbom-from-attestation.json` — SBOM pulled back out of the CycloneDX attestation.
- `labs/lab8/results/my-tool.tar.gz{,.bundle}` + `verify-blob-tampered.txt` — the sign-blob demo.
