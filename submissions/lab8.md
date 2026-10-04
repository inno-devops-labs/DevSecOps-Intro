# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

Run date: **2026-10-04**. Cosign **v3.0.2**, Syft **v1.51.1**, Docker
**29.7.2**, Distribution registry **3.1.2**, arm64. Both tasks and the blob-signing
bonus were executed. Commands below use `cosign` and `syft` for the pinned binaries
installed in `/private/tmp/lab8-bin/`.

Public deliverables: this report and `labs/lab8/keys/cosign.pub`.
The encrypted private key stays in ignored `labs/lab8/keys/cosign.key`; its random
passphrase stays in ignored `labs/lab8/results/key-password.txt`. Both are mode 0600.
Logs, decoded attestations, tarballs and bundles stay under the ignored results
directory. No private material or bulk scan outputs are included in the commit.

## Task 1

### Local registry and digest selection

```bash
docker run -d --name lab8-registry -p 127.0.0.1:5000:5000 registry:3
docker tag bkimminich/juice-shop:v20.0.0 localhost:5000/juice-shop:v20.0.0
docker push localhost:5000/juice-shop:v20.0.0
docker inspect localhost:5000/juice-shop:v20.0.0 \
  --format '{{range .RepoDigests}}{{println .}}{{end}}' \
  | grep '^localhost:5000/'
```

The registry was reachable through **127.0.0.1:5000**. On this Mac,
`localhost:5000` selected an AirPlay listener that returned HTTP 403, so Cosign
uses the explicit IPv4 loopback address. Proxy variables were removed from its
process environment and `NO_PROXY=localhost,127.0.0.1,::1` was set.

Filtering `.RepoDigests` selected the local repository rather than Docker Hub, but
on this Docker version the result still carried the original multi-platform index
digest. The push output explicitly reported that only available single-platform
content was uploaded:

```text
sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
  -> sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

I confirmed the actual local tag's digest with the registry's
`Docker-Content-Digest` response header from
`GET http://127.0.0.1:5000/v2/juice-shop/manifests/v20.0.0`, using OCI/Docker
manifest Accept headers. Signing the stale index digest returned 404; the actual
manifest digest below was signed successfully:

```text
127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

### Key generation and private-key protection

```bash
cosign generate-key-pair --output-key-prefix labs/lab8/keys/cosign
git add labs/lab8/keys/cosign.key
```

The passphrase was supplied through `COSIGN_PASSWORD` without printing it.
The actual staging attempt was refused:

```text
The following paths are ignored by one of your .gitignore files:
labs/lab8/keys/cosign.key
```

This refusal came from `.gitignore`, before any commit hook ran. The Lab 8 branch
starts from `main`, which does not carry Lab 3's `.pre-commit-config.yaml`; I do not
claim that its pre-commit hook detected the key. Only the public key was staged.

### Sign and successfully verify

```bash
DIGEST=$(cat labs/lab8/results/juice-shop-digest.txt)
# COSIGN_PASSWORD is loaded locally from the protected passphrase file.
cosign sign --key labs/lab8/keys/cosign.key --tlog-upload=false \
  --use-signing-config=false --allow-insecure-registry --yes "$DIGEST"
cosign verify --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry "$DIGEST"
```

Signing and verification both exited **0**. Successful verification stdout:

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "image": {
        "docker-manifest-digest": "sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "type": "https://sigstore.dev/cosign/sign/v1"
    },
    "optional": null
  }
]
```

Verification stderr, preserved verbatim:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.

Verification for 127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

The verifier prints an offline-transparency-log check in its summary, but
`--insecure-ignore-tlog` deliberately skips that requirement here. This demonstrates
public-key signature/claim verification, not proof of a Rekor inclusion entry.
`--use-signing-config=false` keeps these local exercises independent of the public
service configuration; no signatures were uploaded to public Rekor.

### Swap the tag and verify again

```bash
docker tag alpine:3.20 localhost:5000/juice-shop:v20.0.0
docker push localhost:5000/juice-shop:v20.0.0
# Read the replacement tag's Docker-Content-Digest from the local registry.
cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
  --allow-insecure-registry "$TAMPERED"
cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
  --allow-insecure-registry "$DIGEST"
```

The replacement digest is:

```text
127.0.0.1:5000/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
```

Replacement verification exited **10**, with this exact output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

The original digest still verified after the overwrite: **exit 0**. Its verified
claim still contained `sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113`.
Evidence is retained in `verify-original-after-swap.json` and the corresponding log.

### What the signature binds to

The signed claim binds the registry identity and immutable manifest digest, which
in turn references the image's configuration and layers. A tag is a mutable pointer:
reusing `v20.0.0` for Alpine changes the resolved digest, and that replacement has no
signature trusted by our public key. Verifying the old digest still succeeds because
its content and signature remain available. If a verifier trusted only a signed tag
name without binding it to a content digest, replacing that tag's content could
reuse the apparent approval for different bytes.

## Task 2

### Recover and validate the SBOM input

The original Lab 4 SBOM file was no longer present locally. It was regenerated
with the **same pinned Syft release and original image digest**, not invented from
the previous report:

```bash
syft docker:bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0 \
  -o cyclonedx-json=labs/lab4/juice-shop.cdx.json
```

This produced CycloneDX **1.7**, **3,068 components**, matching the Lab 4 submission.
Because the local manifest digest differs from its parent index, I also compared
its image-config filesystem layers with Docker's original source image:
**all 24 layer diff IDs match**, and both are **arm64**. The local manifest's config
digest is `sha256:e791a8e05ad422cf6fdf45105294726e7ca938dff538f7dde1d9fd886426b8f9`.
The check is retained in `results/sbom-source-check.json`.

### Attach and verify both attestations

```bash
cosign attest --key labs/lab8/keys/cosign.key --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json --tlog-upload=false \
  --use-signing-config=false --allow-insecure-registry --yes "$DIGEST"
cosign verify-attestation --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry --type cyclonedx "$DIGEST" \
  | jq -r '.payload | @base64d | fromjson | .predicate' \
  > labs/lab8/results/sbom-from-attestation.json
```

| SBOM | Components |
|---|---:|
| Regenerated Lab 4 input | 3068 |
| Verified attestation predicate | 3068 |

The decoded predicate is equal to the complete input JSON object, not just equal
in component count. Both attestation signing and verification commands exited 0.

The second predicate supplied was:

```json
{
  "builder": {
    "id": "https://localhost/lab8-student"
  },
  "buildType": "https://example.com/lab8/local-build",
  "invocation": {
    "configSource": {
      "uri": "https://github.com/whynotgm/DevSecOps-Intro"
    }
  }
}
```

```bash
cosign attest --key labs/lab8/keys/cosign.key --type slsaprovenance \
  --predicate labs/lab8/results/provenance.json --tlog-upload=false \
  --use-signing-config=false --allow-insecure-registry --yes "$DIGEST"
cosign verify-attestation --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry --type slsaprovenance "$DIGEST"
```

This is a **student-authored provenance example**, not evidence that this repository
or builder produced the upstream Juice Shop image, and not a claim of a SLSA level.

### Fields read from verified payloads

CycloneDX statement fields:

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

Provenance statement fields:

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
  "predicateType": "https://slsa.dev/provenance/v0.2"
}
```

I supplied the SBOM and provenance predicate bodies, image reference and `--type`
selection. Cosign supplied the statement `_type`, resolved subject name/digest,
and the `predicateType` URI associated with each selected type. The URIs above were
read from the verified, base64-decoded payloads rather than copied from the lab.
Neither input predicate included a statement wrapper or a subject.

### Incident response at 03:00

Verified SBOM attestations let responders search signed inventories for affected
packages and versions across two thousand image digests; a signature alone only
establishes that the approved artifact bytes are unchanged. That requires complete,
accurate SBOMs from trusted producers and an indexed inventory tied to the image
digests actually deployed, including transitive dependencies. Attestations and
trusted keys must remain available, and signature/type/subject checks must be
performed before relying on their contents. A matching package narrows the incident
scope, but reachable code paths and runtime configuration still determine exposure.

## Bonus

### Sign a release artifact and modify it

The original archive contained `install.sh`:

```bash
#!/bin/bash
echo "installing my-tool"
```

```bash
tar -czf labs/lab8/results/my-tool.tar.gz -C labs/lab8/results install.sh
cosign sign-blob --key labs/lab8/keys/cosign.key --yes --tlog-upload=false \
  --use-signing-config=false --bundle labs/lab8/results/my-tool.tar.gz.bundle \
  labs/lab8/results/my-tool.tar.gz
cosign verify-blob --key labs/lab8/keys/cosign.pub \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle --insecure-ignore-tlog \
  labs/lab8/results/my-tool.tar.gz
```

The archive was created using Python's tarfile implementation with the same single
entry as the equivalent `tar` command above. Original verification exited **0**:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

I changed the script to `echo "attacker-modified installer"` and rebuilt the
archive **without re-signing**. Verification of the modified tarball against the
same bundle exited **1**:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

SHA-256 digests of the two archive byte sequences:

```json
{
  "original": "a160c89552168464c0151ab021cfc9f2670cf18e6c6455a392fd7f80afadc844",
  "tampered": "b702acbd569e3146df6366a1805209c57983f4bff859886090479b6541697193"
}
```

A preserved copy of the original archive is retained locally as
`my-tool-original.tar.gz`; the signature bundle was unchanged during the attack.

### What the consumer needs

Besides the archive, the consumer needs **the signature bundle** and **a trusted
public key**. The bundle can travel over the same CDN/channel as the archive,
because a replacement bundle still cannot validate under the trusted key without
authorised signing. The public key must be established through an independently
trusted channel or pinned in advance; fetching a replacement key alongside the
artifact and trusting it would let an attacker replace the entire set.

### Installation instructions I would publish

First establish the release public key through an independently authenticated
channel and pin it locally. Download the archive and its bundle as files, verify
the downloaded archive using that pinned key, and only after success extract and
run the installer. Keep the verified files in a private temporary directory to
avoid replacement between verification and execution. The step projects commonly
skip is **verification before execution**, including authenticating the verification
key rather than trusting a key served beside the untrusted download.

Example for the local exercise (Cosign 3.0.2, pretrusted `cosign.pub`):

```bash
set -euo pipefail
release_url='https://downloads.example.com/my-tool/v1.0.0'
trusted_key="$HOME/.config/my-tool/cosign.pub"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
curl --fail --location "$release_url/my-tool.tar.gz" -o "$work_dir/my-tool.tar.gz"
curl --fail --location "$release_url/my-tool.tar.gz.bundle" -o "$work_dir/my-tool.tar.gz.bundle"
cosign verify-blob --key "$trusted_key" \
  --bundle "$work_dir/my-tool.tar.gz.bundle" --insecure-ignore-tlog \
  "$work_dir/my-tool.tar.gz"
tar -xzf "$work_dir/my-tool.tar.gz" -C "$work_dir" install.sh
bash "$work_dir/install.sh"
```

`downloads.example.com` is an illustrative publishing endpoint, not a hosted lab
release. The log-ignore flag accommodates this lab's deliberately offline bundle;
a production publishing workflow should include and verify transparency evidence.
Signature verification authenticates publisher-approved bytes; it cannot establish
that those approved bytes are free of malicious code or that the signing key has
not been compromised. See [Sigstore's verification documentation](https://docs.sigstore.dev/cosign/verifying/verify/).

## Cleanup and submission

After verification, the temporary registry was removed with
`docker rm -f lab8-registry`. Evidence and protected signing material remain local
for review or repeat runs. Only `submissions/lab8.md` and `labs/lab8/keys/cosign.pub`
are included in the Lab 8 commit and PR.
