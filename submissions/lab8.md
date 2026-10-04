# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

Local registry `registry:3` on `127.0.0.1:5000`. Tool: Cosign `v3.0.2` (not 3.1.x — that drops `--tlog-upload=false`). Image `bkimminich/juice-shop:v20.0.0`. All signing is key-based and kept off the public Rekor log (`--tlog-upload=false` / `--insecure-ignore-tlog`), since this registry only exists on my laptop.

## Task 1

### The digest I signed, and how I picked it

```
localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```

The image carries two repo digests after being pushed to a second registry, and `{{index .RepoDigests 0}}` returned the **Docker Hub** one (`sha256:fd58bdc9…`). Signing that failed with `404 Not Found` against `localhost:5000`, because that digest does not exist in my local registry — Juice Shop is a multi-platform image and only the single-platform manifest was pushed, so the registry stored it under a different digest. I took the authoritative local digest from the registry's own `Docker-Content-Digest` response header for the `v20.0.0` tag (`GET /v2/juice-shop/manifests/v20.0.0`), which is `sha256:28870b9d…`, and filtered for the `localhost:5000/` repo as 8.1 instructs.

### Successful `cosign verify`

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      },
      "image": {
        "docker-manifest-digest": "sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      },
      "type": "https://sigstore.dev/cosign/sign/v1"
    },
    "optional": null
  }
]
```

### The swap, the failure, and the original still verifying

After `docker tag alpine:3.20 localhost:5000/juice-shop:v20.0.0 && docker push`, the tag resolved to a new digest:
```
signed:  localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
now:     localhost:5000/juice-shop@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
```

Verifying the new (tampered) digest fails, quoted exactly:
```
Error: no signatures found
error during command execution: no signatures found
```

And the original digest still verifies afterwards:
```
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
    --allow-insecure-registry localhost:5000/juice-shop@sha256:28870b9d…
sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe   (ORIGINAL OK)
```

### What the signature is bound to

The signature is bound to the image's **content digest** — the SHA-256 of the manifest — not to the human-readable tag `v20.0.0`. A tag is just a mutable pointer: anyone with push access can repoint it at a completely different image, which is exactly what the alpine swap did. Cosign stores the signature under the digest it signed, so when the tag now resolves to `c64c687…`, Cosign looks for a signature on *that* digest, finds none, and says `no signatures found` — the tamper is caught. If signatures were bound to tags instead, the attacker who repointed the tag would simply have inherited the "valid" signature, and the swapped image would have passed verification — the signature would prove nothing.

## Task 2

### Component counts (must match)

```
lab4 components:     3069
attested components: 3069
```

The CycloneDX SBOM extracted back out of the verified attestation has the same 3069 components as Lab 4's `juice-shop.cdx.json`.

### `predicateType` of each attestation (read from the verified payload)

```
cyclonedx       -> https://cyclonedx.org/bom
slsaprovenance  -> https://slsa.dev/provenance/v0.2
```

### The decoded statement, and where each field came from

From the SLSA attestation's decoded payload:
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    { "name": "localhost:5000/juice-shop",
      "digest": { "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe" } }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2"
}
```

| Field | Value | Who set it |
|---|---|---|
| `_type` | `https://in-toto.io/Statement/v0.1` | **Cosign** — the fixed in-toto Statement envelope type |
| `subject` | the image name + its `sha256` digest | **Cosign** — derived from the image I ran `attest` against |
| `predicateType` | `https://slsa.dev/provenance/v0.2` | **Cosign** — chosen from my `--type slsaprovenance` flag |
| `predicate` (body) | builder / buildType / invocation | **me** — I supplied `/tmp/provenance.json`; Cosign wrapped it |

So I supplied only the predicate body; Cosign filled in the statement wrapper (`_type`, `subject`, `predicateType`), which is why the hint says the predicate file has no `_type` or `subject`.

### The morning after the next Log4Shell

With an SBOM attached as a signed attestation to every image, I can **query my registry for "which of my 2000 images actually ship the vulnerable component and version"** instead of rebuilding and rescanning all of them — a signature alone only tells me an image is unchanged, it says nothing about *what is inside*. The attestation turns "are we affected?" into a lookup over data I already have, signed so I can trust it. But for that to work at 3am, several preconditions must already be true: the SBOMs must have been generated and attached *before* the incident (you can't attest retroactively on an image you no longer build the same way), they must be complete and accurate (an SBOM that misses a transitive dependency hides the very thing you're searching for), and I must still hold — and trust — the public key to verify them, plus somewhere to run the query across all 2000 digests. The attestation is only as useful as the discipline that produced it ahead of time.

## Bonus

### Verified OK, then the exact failure

Original tarball:
```
$ cosign verify-blob --key labs/lab8/keys/cosign.pub \
    --bundle labs/lab8/results/my-tool.tar.gz.bundle --insecure-ignore-tlog \
    labs/lab8/results/my-tool.tar.gz
Verified OK
```

After modifying `install.sh` and rebuilding the tarball **without re-signing**:
```
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### The two files a consumer needs

1. the **artifact** itself (`my-tool.tar.gz`), and
2. the **signature bundle** (`my-tool.tar.gz.bundle`).

They also need the **public key** (`cosign.pub`) to verify against. The artifact and the bundle may travel over the same channel as each other (the CDN), because tampering with either one breaks verification. The one thing that must **not** come down that same channel is the public key — if the attacker who can swap the tarball can also swap the key you check it with, the whole scheme collapses.

### Install instructions that cannot be given a modified script

> 1. Obtain our public key once, from a channel independent of the download CDN — e.g. our keys are published in this repo / pinned in our docs / distributed as an OIDC identity for keyless verification — and keep it.
> 2. Download both `my-tool.tar.gz` and `my-tool.tar.gz.bundle`.
> 3. **Verify before executing:** `cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz`
> 4. Only if it prints `Verified OK`, extract and run it. Never `curl … | bash`.

The step most projects skip is **step 1 and 3 together** — distributing the public key over an independent, trusted channel and actually running the verification before execution. Codecov's uploader was signed by nobody and verified by nobody; even projects that sign often publish the key next to the artifact on the same CDN, which defeats the point. The hard part of signing is not signing — it is **key distribution**: the verifier must get the public key through a path the artifact's attacker does not control.
