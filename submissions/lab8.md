# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

## Task 1

```bash
docker push localhost:5000/juice-shop:v20.0.0
```
```text
 Info -> Not all multiplatform-content is present and only the available single-platform image was pushed
         sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0 -> sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```

The push output shows the situation: the local image is the multi-platform index `fd58bdc9…` (same digest as Docker Hub and Lab 4), but only the linux/amd64 manifest `28870b9d…` was pushed. The lab's inspect command does not make this obvious:

```text
$ docker inspect localhost:5000/juice-shop:v20.0.0 --format '{{range .RepoDigests}}{{println .}}{{end}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

`{{index .RepoDigests 0}}` returns the Docker Hub line, which is the pitfall. Selecting the `localhost:5000/` entry fixes the repository name but not the digest, since the registry does not have `fd58bdc9…`. The registry itself is the reliable source:

```text
$ curl -sI -H 'Accept: …oci.image.index…, …oci.image.manifest…' http://127.0.0.1:5000/v2/juice-shop/manifests/v20.0.0
Content-Type: application/vnd.oci.image.manifest.v1+json
Docker-Content-Digest: sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe

HEAD …/manifests/sha256:fd58bdc9…  -> 404
HEAD …/manifests/sha256:28870b9d…  -> 200
```

Signing the inspect digest fails for this reason:

```text
Error: signing [localhost:5000/juice-shop@sha256:fd58bdc9…]: signing digest: HEAD http://localhost:5000/v2/juice-shop/manifests/sha256:fd58bdc9…: unexpected status code 404 Not Found
```

Digest signed: `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`, taken from the `Docker-Content-Digest` header before any tampering. Recorded in `labs/lab8/results/juice-shop-digest.txt`.


```bash
cd labs/lab8/keys && cosign generate-key-pair && cd -   # passphrase via COSIGN_PASSWORD
```

This produced `cosign.key` (`-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----`) and `cosign.pub`. Only `cosign.pub` is committed. 

On this branch, `.gitignore` is the only control that fires. Lab 3's gitleaks rule would catch a forced add, but only where that config is present. The key is also passphrase-encrypted, which limits the impact of a leak.

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



```text
$ docker tag alpine:3.20 localhost:5000/juice-shop:v20.0.0 && docker push localhost:5000/juice-shop:v20.0.0
v20.0.0: digest: sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e

signed:  localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
now:     localhost:5000/juice-shop@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
```

The "now" digest was also taken from the registry; `docker inspect` reported the local alpine index `d9e853e8…`, which the registry answers with 404.

```text
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog --allow-insecure-registry localhost:5000/juice-shop@sha256:c64c687c…
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
# exit code 10
```

Verification by tag (`localhost:5000/juice-shop:v20.0.0`), which is what a tag-referencing deployment would check, gives the same `Error: no signatures found`.

The originally signed digest still verifies after the swap:

```text
$ cosign verify ... localhost:5000/juice-shop@sha256:28870b9d…
{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d…"},"image":{"docker-manifest-digest":"sha256:28870b9d…"},"type":"https://sigstore.dev/cosign/sign/v1"}
Verification for localhost:5000/juice-shop@sha256:28870b9d… --
```

What the signature is bound to: a payload naming one manifest digest — the SHA-256 of the manifest bytes, which in turn pin the digests of the config and every layer. Any change to the image produces a different digest. Cosign also stores the signature under that digest; in the registry it appears under the tag `sha256-28870b9d…` as an index of referrers whose `subject` is `sha256:28870b9d…`.

A tag is a mutable pointer. When it moved to alpine, verification followed it to `c64c687c…`, found no signatures stored for that digest, and failed. If signatures were bound to tags, the alpine push would have inherited the "signed" status, and anyone with push access to the repository could swap the image without the key. Verification and deployment should therefore both reference the digest.

## Task 2


```bash
cosign attest --key labs/lab8/keys/cosign.key --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"
cosign verify-attestation --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
  --allow-insecure-registry --type cyclonedx "$DIGEST" \
  | jq -r '.payload | @base64d | fromjson | .predicate' > labs/lab8/results/sbom-from-attestation.json
```

| | `.components \| length` |
|---|---|
| `labs/lab4/juice-shop.cdx.json` | 3069 |
| `labs/lab8/results/sbom-from-attestation.json` | 3069 |

The counts match, and after `jq -S` normalisation the two files are identical JSON. The SBOM is carried in full.

The second attestation was SLSA provenance, with `invocation.configSource.uri` set to `https://github.com/mobgun/DevSecOps-Intro`. Each `predicateType` was read from its own verified payload (`jq -r '.payload | @base64d | fromjson | .predicateType'`):

| `--type` | `predicateType` in the verified payload |
|---|---|
| `cyclonedx` | `https://cyclonedx.org/bom` |
| `slsaprovenance` | `https://slsa.dev/provenance/v0.2` |

Note that the `slsaprovenance` alias maps to v0.2, not v1.0.

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
| `_type` | Cosign. It wraps the predicate in an in-toto Statement (v0.1); the input file had no `_type`. |
| `subject` | Cosign, from the image reference passed on the command line: repository name and digest `28870b9d…`. This binds the claim to one exact image. |
| `predicateType` | Cosign, expanded from the `--type` alias (`cyclonedx` → `https://cyclonedx.org/bom`, `slsaprovenance` → `…/provenance/v0.2`). |
| `predicate` | The file passed to `--predicate`, carried byte for byte. For the SBOM, all 3069 components. |

Cosign then placed the Statement in a DSSE envelope (`payloadType: application/vnd.in-toto+json`, one signature) and signed it with the key.

In the registry, the signature and both attestations are three Sigstore bundle v0.3 referrers with `subject` `sha256:28870b9d…`, indexed under the single tag `sha256-28870b9d…`. None of them reference `v20.0.0`.





A signature only establishes that an image is unchanged since it was signed; it says nothing about the contents. With an SBOM attested to every image digest, the procedure is: iterate over the two thousand digests, run `verify-attestation --type cyclonedx` on each, and search the verified predicates for the vulnerable package and version. This produces a list of affected digests in minutes, without pulling or unpacking any image. The result is also trustworthy: each SBOM is signed by the build key and bound to its exact digest, so an image that was swapped or rebuilt without re-attestation appears as "no attestation" rather than as clean.

This depends on several preconditions. Every image was attested at build time; coverage gaps are invisible until needed, the SBOMs were generated from the final images and capture nested and shaded jars; Log4j was distributed inside fat jars, the verification key is available, and the registry and its referrers still exist, a mapping exists from digest to running workloads; without it, "affected" cannot be turned into a list of deployments.