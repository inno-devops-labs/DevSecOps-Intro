# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

> Environment note: on this machine, macOS's AirPlay Receiver (`ControlCenter`) already listens on `*:5000`, so the local registry was run on host port **5001** instead (`-p 127.0.0.1:5001:5000`). All references to `localhost:5000` in the lab instructions are `localhost:5001` below.

## Task 1

**The digest I signed, and how I picked it out of two.**

After `docker tag` + `docker push`, `docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}'` returned:

```
localhost:5001/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

That digest looked like the local-registry one (it's prefixed `localhost:5001/`), but it is actually a stale copy of the **Docker Hub multi-platform index digest** — Juice Shop's `v20.0.0` tag is a multi-arch manifest list, and Docker's local image store keeps that original digest attached to the `RepoDigests` field even after a single-platform image is pushed under a new repo name. `cosign sign` on it failed with `404 Not Found`, because that digest never existed on `localhost:5001`.

I confirmed the digest actually stored in my registry by asking the registry itself:

```bash
curl -sD - -o /dev/null \
  -H "Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json" \
  http://localhost:5001/v2/juice-shop/manifests/v20.0.0 | grep -i docker-content-digest
# Docker-Content-Digest: sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

This matched the digest `docker push` itself printed (`v20.0.0: digest: sha256:cbdfc00d...`). I signed **that** one:

```
localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

**Successful `cosign verify` output:**

```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.

Verification for localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

**Failure on the swapped image (`alpine:3.20` pushed as `v20.0.0`), quoted exactly:**

```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

The tag now resolved to `sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d`, which has no signature attached because nothing was ever signed under that digest.

**And the original digest I signed still verifies afterwards** (same output as above, re-run after the swap):

```
Verification for localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

**Explanation.** `v20.0.0` is a mutable pointer — anyone with push access can repoint it at a completely different image, as I just did by tagging and pushing `alpine:3.20` over it. Cosign never signs a tag: it signs a content digest (a SHA-256 hash of the immutable manifest), and stores the signature as a separate object in the registry, keyed off that same digest. So `cosign verify` on the tag's *current* digest correctly reports "no signatures found," because that digest — the Alpine image — was never signed, while the *original* digest I signed still verifies, because the bytes behind it never changed even though the tag no longer points at them. If Cosign instead bound signatures to tags, the swap would have kept the old signature "attached" to `v20.0.0`, and `cosign verify` would have happily said the Alpine image was Juice Shop — the exact class of attack (trusted name, swapped content) that the Codecov incident (see Bonus) exploited.

## Task 2

**Component counts:**

```
jq '.components | length' labs/lab4/juice-shop.cdx.json            -> 3068
jq '.components | length' labs/lab8/results/sbom-from-attestation.json -> 3068
```

Both match — the CycloneDX SBOM comes back out of the registry byte-for-byte equivalent (as JSON structure) to the one I attached.

**`predicateType` of each attestation, read from the verified payload:**

- CycloneDX attestation: `https://cyclonedx.org/bom`
- SLSA provenance attestation: `https://slsa.dev/provenance/v0.2`

**Decoded statement fields, and where each came from:**

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "localhost:5001/juice-shop",
      "digest": { "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113" }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom"
}
```

(the SLSA attestation's statement is identical except `predicateType` is `https://slsa.dev/provenance/v0.2`.)

- `_type` — always `https://in-toto.io/Statement/v0.1`. Fixed by the in-toto attestation spec; Cosign fills it in, I never supplied it.
- `subject` — the image name and digest I was attesting about. Cosign derived this from the `$DIGEST` argument I passed to `cosign attest`; I never typed it into a predicate file.
- `predicateType` — came from the `--type` flag I chose (`cyclonedx` / `slsaprovenance`); Cosign maps those short names to the full predicate-type URIs.
- The **predicate body itself** (the CycloneDX SBOM, or my hand-written `provenance.json`) is the one part entirely mine — I supplied it via `--predicate`. Everything wrapping it (`_type`, `subject`, `predicateType`) is Cosign's, generated at attest time so the statement can't be forged by editing the predicate alone.

**Incident response, the morning after the next Log4Shell.** A signature alone tells me an image's bytes are unmodified from whatever was pushed — it says nothing about *what's inside*. With a signed CycloneDX attestation on every image, I can run one offline query — `cosign verify-attestation --type cyclonedx | jq` across the fleet, or a Rekor/registry index of it — to list every image whose SBOM names the vulnerable `log4j-core` version, without pulling and unpacking two thousand images or trusting whatever's printed on a wiki page. For that to actually work at 3am, three things have to already be true: the attestation has to have been generated and attached at build time for *every* image (not just newly built ones — old images pushed before this pipeline existed have nothing to query); the public key (or Rekor/Fulcio identity) used to verify has to be pinned somewhere I control, not re-fetched from the same compromised registry; and the SBOM has to be accurate — generated from the actual build inputs, not a stale template — or the whole query silently under-counts.

## Bonus

**`Verified OK` on the original, and the exact error on the modified tarball:**

```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

After editing `/tmp/install.sh` (added a `curl | sh` line) and rebuilding `my-tool.tar.gz` without re-signing:

```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

**The two files a consumer needs, and which may travel over the same channel as the artifact.**

A consumer needs (1) the artifact itself (`my-tool.tar.gz`) and (2) the signature bundle (`my-tool.tar.gz.bundle`, containing the signature and the certificate/public-key material). The **bundle may travel over the same channel** as the artifact — a modified bundle just fails verification, it can't forge a valid one without the private key. What must **not** travel over that same, potentially-compromised channel is the **public key** (or trust root) used to verify: if an attacker can modify the artifact on a CDN, they can just as easily replace the bundle *and* swap in their own public key next to it, and `cosign verify` would happily pass. The verification key has to be pinned somewhere the artifact's own distribution channel cannot touch — vendored into the install script ahead of time, published on a separate domain, or (for keyless signing) resolved through Fulcio/Rekor's independent transparency log rather than trusted from the download itself.

**Install instructions, and the step most projects skip.**

```bash
# 1. Fetch cosign.pub ONCE, out-of-band (e.g. pinned in this repo, not from the CDN
#    that serves my-tool.tar.gz), and keep it — never re-download it alongside the artifact.
# 2. Download the artifact and its signature bundle.
curl -sSLO https://dl.example.com/my-tool.tar.gz
curl -sSLO https://dl.example.com/my-tool.tar.gz.bundle
# 3. Verify BEFORE extracting or executing anything.
cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz \
  || { echo "signature verification failed, refusing to run"; exit 1; }
# 4. Only now:
tar -xzf my-tool.tar.gz && ./install.sh
```

Codecov's uploader was signed by nobody and verified by nobody — `curl | bash` ran whatever the CDN served, full stop. The step almost every project skips isn't producing a signature (that part is one `cosign sign-blob` call) — it's **shipping the verification key through a channel independent of the artifact's own distribution**, and then actually failing closed (`exit 1`, not a warning) when verification doesn't pass. A signed artifact next to an unverified install script is no safer than no signature at all.
