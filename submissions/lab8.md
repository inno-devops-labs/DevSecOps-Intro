# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

Branch: `feature/lab8`. Executed on 2026-10-02 (Europe/Moscow; registry and
Rekor timestamps are 2026-10-01 UTC). Task 1, the optional Task 2, and the bonus
are all done.

Image: `bkimminich/juice-shop:v20.0.0`, the same image as Lab 4. The digest
signed and attested below is the Linux/amd64 manifest
`sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`, which is
the manifest Lab 4 recorded and generated its SBOM from.

| Tool | Version | How it ran |
| --- | --- | --- |
| Cosign | **v3.0.2** (GitCommit `84449696`, go1.25.1), `ghcr.io/sigstore/cosign/cosign:v3.0.2` | container with `--network container:lab8-registry`, so `localhost:5000` inside it is the lab registry |
| Registry | `registry:3` (distribution 3.1.2) | `127.0.0.1:5000` |
| jq | 1.8.1 (`ghcr.io/jqlang/jq:1.8.1`) | container |
| Docker | Engine 29.7.2, containerd image store | host |

Public key, committed as `labs/lab8/keys/cosign.pub`:

```text
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6zxvJjy206HS2uWXRvJu2RPHlcLD
4gWUlJIJVzZO/5Z3H+dVLVhcDU0qgv/CtmR5+jjEJFRVEjqZkCoqNC/Rfw==
-----END PUBLIC KEY-----
```

The private key is protected by a random passphrase and is git-ignored, like the
raw outputs in `labs/lab8/results/`.

### Where this run departs from the lab text

1. **The 8.1 filter gave a digest that is not in the registry.** Under Docker's
   containerd image store, `docker push` sent only the amd64 manifest, but
   `docker inspect` still lists the multi-platform index digest under
   `localhost:5000`. I signed the digest the registry actually serves for the
   tag (details in Task 1).
2. **`--tlog-upload=false` did not keep the first signature off public Rekor.**
   Cosign 3.0.2 ignores the flag unless `--use-signing-config=false` is also
   passed. The 8.2 signature is in the public log at index `3043580677`. Every
   later signing command used `--use-signing-config=false --tlog-upload=false`
   and ran with no route to the internet, and none of those produced a log
   entry. Evidence and impact are in [Rekor](#the-signature-reached-public-rekor-anyway).
3. `/tmp` was replaced by a scratch directory. The provenance predicate is
   saved as `labs/lab8/results/provenance-predicate.json`.

## Task 1

### 8.1 Picking the digest

`docker inspect` lists two repo digests, but they share one hash:

```text
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

The `grep '^localhost:5000/'` filter correctly drops the Docker Hub entry, so
Cosign is never sent to Docker Hub. The hash it keeps is still wrong. `fd58bdc9…` is the
multi-platform **index**, and `docker push` said it pushed only the platform
manifest:

```text
v20.0.0: digest: sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe size: 4847
 Info -> Not all multiplatform-content is present and only the available single-platform image was pushed
         sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0 -> sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```

Asking the registry directly gives `HEAD …/manifests/sha256:fd58bdc9…` → **404**
and `HEAD …/manifests/v20.0.0` → `Docker-Content-Digest: sha256:28870b9d…`.
Signing the `docker inspect` digest fails accordingly:

```text
Error: signing [localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0]: signing digest: HEAD http://localhost:5000/v2/juice-shop/manifests/sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0: unexpected status code 404 Not Found (HEAD responses have no body, use GET for details)
```

So I took the local-registry name and asked the registry, not the local image
store, for its digest:

```bash
echo "localhost:5000/juice-shop@$(docker buildx imagetools inspect \
  localhost:5000/juice-shop:v20.0.0 --format '{{.Manifest.Digest}}')" \
  > labs/lab8/results/juice-shop-digest.txt
```

**Signed digest:**
`localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`

### 8.2 Sign and verify

`cosign sign --key labs/lab8/keys/cosign.key --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"`
printed `Signing artifact...` and exited 0. `cosign verify`, stdout:

```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

stderr:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.

Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

The "transparency log was verified offline" line is boilerplate. Cosign prints it
for the Task 2 attestations too, and those have no log entry at all.

Cosign 3 does not write the old `.sig` tag. It stores a Sigstore bundle
(v0.3, DSSE envelope) as an OCI referrer. The registry now has the tag
`sha256-28870b9d…`, which points to an index of referrer manifests. Each manifest
has `"subject": {"digest": "sha256:28870b9d…"}`, and the signed DSSE payload
names only the digest:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "digest": { "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe" } }],
  "predicateType": "https://sigstore.dev/cosign/sign/v1"
}
```

### Lab 3's hook and `cosign.key`

```text
$ git add labs/lab8/keys/cosign.key
The following paths are ignored by one of your .gitignore files:
labs/lab8/keys/cosign.key
```

`git add` refuses the key before any hook runs. To see what the hook does if the
key is forced in with `git add -f`, I staged a throwaway Cosign key in a scratch
repository using this repository's `.pre-commit-config.yaml` and ran
`pre-commit run`. Nothing was staged or committed here.

```text
Detect hardcoded secrets.................................................Failed
- hook id: gitleaks
RuleID:      private-key
File:        cosign.key
WRN leaks found: 2
detect private key.......................................................Passed
```

gitleaks blocks the commit. `detect-private-key` **does not**. Cosign's header
is `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----`, and none of the hook's
fixed patterns (the RSA, EC, OpenSSH, PKCS#8 and encrypted PKCS#8 PEM headers,
…) is a substring of it. One of the two hooks catches it, and `.gitignore` sits
in front of both. The reverse also happened: `detect-private-key` blocked the
first commit of this file, because an earlier draft quoted two of those
patterns word for word. It flags a document that describes a key but not the
key itself.

### 8.3 Swap the image

```text
signed:  localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
now:     localhost:5000/juice-shop@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
```

`c64c687c…` is the registry's digest for `alpine:3.20` now behind the tag. (The
lab's `docker inspect` line gives the Alpine index `d9e853e8…` for the same
reason as in 8.1.) Verifying the swapped image fails:

```text
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
    --allow-insecure-registry localhost:5000/juice-shop@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

Exit code 10. The same error comes back for the `docker inspect` digest
`d9e853e8…` and for the tag `localhost:5000/juice-shop:v20.0.0` itself. A
consumer who verifies by tag is also refused, because Cosign first resolves the
tag to `c64c687c…`.

The original digest still verifies after the swap:

```text
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
    --allow-insecure-registry "$(cat labs/lab8/results/juice-shop-digest.txt)"
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]

Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

**What the signature is bound to.** The signature covers the manifest digest
`sha256:28870b9d…`, a hash of the exact manifest bytes. Those bytes pin the
config and every layer by their own hashes, so changing any file in the image
changes the digest. The tag `v20.0.0` is just a mutable pointer that anyone with
push access can move. After the swap, Cosign followed the tag to `c64c687c…`,
found no signature for that content, and refused, while `28870b9d…` still
verifies because its bytes never changed. If signatures were bound to tags,
the attacker's push would inherit the signature. "Is `v20.0.0` signed?" would
answer yes for Alpine or a backdoored Juice Shop, and the signature would vouch
for exactly the part the attacker controls.

### The signature reached public Rekor anyway

The bundle Cosign stored for the 8.2 signature contains a transparency-log
entry, despite `--tlog-upload=false`:

```text
tlogEntries: logIndex 3043580677, kind dsse 0.0.1, integratedTime 1790897927 (2026-10-01T23:38:47Z),
             inclusionProof + checkpoint signed by "rekor.sigstore.dev - 1193050959916656506"
```

A read-only `GET https://rekor.sigstore.dev/api/v1/log/entries?logIndex=3043580677`
returns the entry. Its `verifier` is byte-for-byte `labs/lab8/keys/cosign.pub`,
and its `payloadHash` `22064b32…95dd` equals the SHA-256 of the DSSE payload
shown in 8.2.

**Cause.** The flag is ignored while `--use-signing-config=true`, which is the
default in Cosign 3.0.x. Cosign then fetches the signing config from Sigstore's
TUF repository and uploads to the Rekor it names. I checked this with
`sign-blob` in a container with **no network** (`--network none`):

| Flags | Result with no network |
| --- | --- |
| `--tlog-upload=false` (as in the lab) | `Error: error getting signing config from TUF: … Get "https://tuf-repo-cdn.sigstore.dev/13.root.json": … network is unreachable` |
| `--use-signing-config=false --tlog-upload=false` | `Wrote bundle to file …`; the bundle has no `tlogEntries` |

**Impact.** Rekor is append-only, so the entry is permanent. It holds the
public key (which is in this PR anyway), the signature, and two hashes. It does
not contain the image name or `localhost:5000`. Anyone who hashes a statement
for the public Juice Shop amd64 digest can, however, learn that this key signed
it at 23:38:47 UTC. That is low impact for a throwaway lab key, but it is
exactly what the lab says these flags prevent. All later signing commands
(Task 2, the bonus) used `--use-signing-config=false --tlog-upload=false`. For
Task 2, the registry was also disconnected from the bridge network, so neither
it nor the Cosign container sharing its network namespace had a route out.

## Task 2

The registry was taken offline with `docker network disconnect bridge lab8-registry`
(host → `127.0.0.1:5000` fails, `rekor.sigstore.dev` unreachable from inside, the
registry still reachable at `localhost:5000`). Then:

```bash
cosign attest --key labs/lab8/keys/cosign.key --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json \
  --use-signing-config=false --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"

cosign attest --key labs/lab8/keys/cosign.key --type slsaprovenance \
  --predicate provenance.json \
  --use-signing-config=false --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"
```

Both exited 0. The registry was reconnected for verification, which only reads.
`verify-attestation` fetches Sigstore's trusted root even with
`--insecure-ignore-tlog`, and offline it fails with
`trusted root is required when using new bundle format`. Both verifications
pass:

```text
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

### Component counts

```text
$ jq '.components | length' labs/lab4/juice-shop.cdx.json
3069
$ jq '.components | length' labs/lab8/results/sbom-from-attestation.json
3069
```

The counts match. The match is not just a count: the canonical form of each
file (`jq -S -c .`) has the same SHA-256,
`1d69bfcfc16f6267f29a6d94c8b2687506c5de16f117ef0be0c03dab013291a5`. Cosign
attested the Syft CycloneDX 1.7 document unchanged.

### `predicateType` from the verified payloads

```text
$ cosign verify-attestation … --type cyclonedx "$DIGEST" | jq -r '.payload | @base64d | fromjson | .predicateType'
https://cyclonedx.org/bom
$ cosign verify-attestation … --type slsaprovenance "$DIGEST" | jq -r '.payload | @base64d | fromjson | .predicateType'
https://slsa.dev/provenance/v0.2
```

### The decoded statement, by origin

The CycloneDX statement with the 1.8 MB predicate removed. The SLSA one is
identical apart from `predicateType`.

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": { "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe" }
    }
  ]
}
```

| Field | Value | Who supplied it |
| --- | --- | --- |
| `_type` | `https://in-toto.io/Statement/v0.1` | Cosign. It is fixed by `cosign attest`; note that `cosign sign` in the same release writes `Statement/v1` (8.2). |
| `subject[].name` | `localhost:5000/juice-shop` | Cosign, from the repository part of the image reference I passed |
| `subject[].digest.sha256` | `28870b9d…` | Cosign, from the digest in that reference. I chose which image; Cosign wrote the hash. This is the binding to the image. |
| `predicateType` | `https://cyclonedx.org/bom` / `https://slsa.dev/provenance/v0.2` | Cosign, mapping my `--type cyclonedx` / `--type slsaprovenance` to the URI |
| `predicate` | the SBOM / the provenance body | Me, the `--predicate` file verbatim, which is why the provenance file has no `_type` or `subject` |
| envelope `payloadType`, signature | `application/vnd.in-toto+json`, ECDSA P-256 | Cosign, signing with my key |

The verified provenance predicate carries the URI I supplied,
`https://github.com/etern1ty22/DevSecOps-Intro`.

The registry now holds three referrers on the same subject, one per signed
statement:

| Referrer manifest | `predicateType` | Rekor entries in the bundle |
| --- | --- | --- |
| `sha256:0e861382…` | `https://sigstore.dev/cosign/sign/v1` (8.2) | 1 (index 3043580677) |
| `sha256:b76010f4…` | `https://cyclonedx.org/bom` | none |
| `sha256:f8a2ef77…` | `https://slsa.dev/provenance/v0.2` | none |

### The morning after the next Log4Shell

A signature only proves that image `28870b9d…` is the one we built. The
CycloneDX attestation adds a signed inventory of what is inside it. With
attestations on all 2,000 images, I can fetch and verify one small document per
digest and query it for the vulnerable package and version, instead of pulling
and rescanning 2,000 images. Because the attestation is signed and bound to the
digest, a stale or substituted SBOM fails verification rather than giving me a
wrong "not affected". For that to work at three in the morning, every image
must actually have been attested at build time, by a generator that sees
shaded or nested jars. The public key or signing identity must be available and
trusted. And I need a current map of which digests are running where. Any
image without an attestation is an unknown that still has to be scanned the
slow way.

## Bonus

The tarball was built from a scratch-directory `install.sh`. Signing ran in a
Cosign container with `--network none`:

```bash
cosign sign-blob --key labs/lab8/keys/cosign.key --yes \
  --use-signing-config=false --tlog-upload=false \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle labs/lab8/results/my-tool.tar.gz
cosign verify-blob --key labs/lab8/keys/cosign.pub \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle --insecure-ignore-tlog \
  labs/lab8/results/my-tool.tar.gz
```

Original tarball, SHA-256 `7ee8cfcf…50fc`:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

Then the attacker step. I appended a line to `install.sh`, rebuilt
`my-tool.tar.gz` under the same name (SHA-256 `96b744d5…41b6`), left the old
bundle in place, and ran the same verify:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

Exit code 1. The saved original still prints `Verified OK` with the same bundle.

### What a consumer needs, and over which channel

A consumer needs `my-tool.tar.gz.bundle` (signature plus verification
material) and `cosign.pub`, besides the artifact itself. **The bundle may travel
with the artifact** on the same CDN or release page, because tampering with it
only makes verification fail. **The public key must not.** I checked both cases.
An attacker who re-signs the modified tarball with their own key and ships
their own bundle gets the same `invalid signature` error against our
`cosign.pub`. If the victim fetched the attacker's `.pub` from the same
compromised CDN, the result is `Verified OK`. Signing only moves the problem to
distributing the key.

### Install instructions that cannot hand you a modified script

```bash
# Once: the key comes from the git repository, not the download CDN, and its
# fingerprint must match the one in the README and release notes.
curl -fsSLO https://raw.githubusercontent.com/<org>/my-tool/main/cosign.pub
sha256sum cosign.pub
# Every install: download to disk, verify, and only then run. Never curl | bash.
curl -fsSLO https://cdn.example.com/my-tool/v1.2.3/my-tool.tar.gz
curl -fsSLO https://cdn.example.com/my-tool/v1.2.3/my-tool.tar.gz.bundle
cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz \
  && tar -xzf my-tool.tar.gz && bash install.sh
```

Codecov's uploader was piped straight from a CDN into `bash`, so no step
existed where a check could run. These instructions add one and chain execution
to its success with `&&`. In production I would also drop
`--insecure-ignore-tlog` and keep the Rekor entry for auditability. The step most
projects skip is pinning the verification key, or with keyless signing the
`--certificate-identity` and `--certificate-oidc-issuer`, through a channel the
attacker does not control. A project that publishes `cosign.pub` next to the
tarball on the same CDN has published a signature that whoever modifies the
script can replace as well.
