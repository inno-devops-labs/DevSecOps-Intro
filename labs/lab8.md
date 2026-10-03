# Lab 8 — Supply Chain: Signing, Tampering, and Attestation

![difficulty](https://img.shields.io/badge/difficulty-intermediate-yellow)
![topic](https://img.shields.io/badge/topic-Supply%20Chain-blue)
![points](https://img.shields.io/badge/points-10%2B2-orange)
![tech](https://img.shields.io/badge/tech-Cosign%20%2B%20Registry-informational)

> **Goal:** Sign the Juice Shop image in a local registry, prove a swapped image fails verification, attach the Lab 4 SBOM as a signed attestation, and sign a release artifact the way the Codecov incident should have been prevented.
> **Deliverable:** A PR from `feature/lab8` with `submissions/lab8.md` and `labs/lab8/keys/cosign.pub`. Submit the PR link via Moodle.
> **Builds on:** the SBOM from Lab 4.

## Setup

- Docker and `jq`.
- **Cosign 3.0.x**: `brew install cosign` or the [releases page](https://github.com/sigstore/cosign/releases). Not 3.1.x, which removed `--tlog-upload=false` and breaks every command below.

<!-- verify:skip student fork branch -->
```bash
git switch main && git pull
git switch -c feature/lab8
```

```bash
cosign version | grep GitVersion    # must be v3.0.x
mkdir -p labs/lab8/keys labs/lab8/results
```

## Task 1 — Sign an image, then try to swap it (6 pts)

### 8.1 A registry of your own

```bash
docker run -d --name lab8-registry -p 127.0.0.1:5000:5000 registry:3
docker pull bkimminich/juice-shop:v20.0.0
docker tag bkimminich/juice-shop:v20.0.0 localhost:5000/juice-shop:v20.0.0
docker push localhost:5000/juice-shop:v20.0.0

docker inspect localhost:5000/juice-shop:v20.0.0 \
  --format '{{range .RepoDigests}}{{println .}}{{end}}' \
  | grep '^localhost:5000/' | tee labs/lab8/results/juice-shop-digest.txt
```

The image now has two repo digests, one for Docker Hub and one for your registry, and `{{index .RepoDigests 0}}` returns whichever it was pulled with. Sign the wrong one and Cosign goes to talk to Docker Hub, where you cannot push.

### 8.2 A key, and a signature over the digest

```bash
cd labs/lab8/keys && cosign generate-key-pair && cd -
ls labs/lab8/keys
```

`cosign.key` is a private key. Lab 3's pre-commit hook should refuse it: try `git add labs/lab8/keys/cosign.key` and watch.

<!-- verify:skip needs the key pair and passphrase from 8.2 -->
```bash
DIGEST=$(cat labs/lab8/results/juice-shop-digest.txt)
COSIGN_PASSWORD="<your passphrase>" cosign sign \
  --key labs/lab8/keys/cosign.key --tlog-upload=false \
  --allow-insecure-registry --yes "$DIGEST"

cosign verify --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry "$DIGEST" \
  | tee labs/lab8/results/verify-original.json
```

`--tlog-upload=false` and `--insecure-ignore-tlog` keep this off the public Rekor transparency log, which has no business knowing about a registry on your laptop. In CI with keyless signing, Rekor is the point and you would not pass either flag.

### 8.3 Swap the image

<!-- verify:skip needs the signature from 8.2 -->
```bash
# Overwrite the tag you signed. This is the attack: same name, different image.
docker pull alpine:3.20
docker tag alpine:3.20 localhost:5000/juice-shop:v20.0.0
docker push localhost:5000/juice-shop:v20.0.0

# The tag now resolves to a different digest
TAMPERED=$(docker inspect localhost:5000/juice-shop:v20.0.0 \
  --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep '^localhost:5000/')
echo "signed:  $(cat labs/lab8/results/juice-shop-digest.txt)"
echo "now:     $TAMPERED"

cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
  --allow-insecure-registry "$TAMPERED" 2>&1 \
  | tee labs/lab8/results/verify-tampered.txt

# And the digest you signed still verifies, because a signature is not a tag
cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
  --allow-insecure-registry "$(cat labs/lab8/results/juice-shop-digest.txt)"
```

**Submit** in `submissions/lab8.md`, section `## Task 1`:

- The digest you signed, and how you picked it out of the two the image carries.
- The successful `cosign verify` output.
- The failure on the swapped image, quoted exactly, and the proof that the original digest still verifies afterwards.
- Three or four sentences: the tag `v20.0.0` now points at a different image than the one you signed, and Cosign noticed. Explain to someone who has not done this lab what the signature is actually bound to, and what would have happened if signatures were bound to tags instead.

## Task 2 — Attach the SBOM as an attestation (4 pts)

Optional. A signature says an artifact is unchanged. An attestation says something *about* it.

<!-- verify:skip needs the key pair and the Lab 4 SBOM -->
```bash
DIGEST=$(cat labs/lab8/results/juice-shop-digest.txt)

COSIGN_PASSWORD="<your passphrase>" cosign attest \
  --key labs/lab8/keys/cosign.key --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json \
  --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"

cosign verify-attestation --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry --type cyclonedx "$DIGEST" \
  | jq -r '.payload | @base64d | fromjson | .predicate' \
  > labs/lab8/results/sbom-from-attestation.json

jq '.components | length' labs/lab4/juice-shop.cdx.json
jq '.components | length' labs/lab8/results/sbom-from-attestation.json
```

Then attach a second attestation of a different kind, so you have seen that the
predicate is yours to choose:

<!-- verify:skip needs the key pair -->
```bash
cat > /tmp/provenance.json <<'JSON'
{
  "builder": { "id": "https://localhost/lab8-student" },
  "buildType": "https://example.com/lab8/local-build",
  "invocation": { "configSource": { "uri": "https://github.com/<you>/DevSecOps-Intro" } }
}
JSON

COSIGN_PASSWORD="<your passphrase>" cosign attest \
  --key labs/lab8/keys/cosign.key --type slsaprovenance \
  --predicate /tmp/provenance.json \
  --tlog-upload=false --allow-insecure-registry --yes "$DIGEST"

cosign verify-attestation --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry --type slsaprovenance "$DIGEST" \
  | jq -r '.payload | @base64d | fromjson | .predicateType'
```

`--type slsaprovenance` expects only the predicate body. Cosign wraps it in the
statement itself, which is why the file above has no `_type` or `subject`.

**Submit**, section `## Task 2`:

- Both component counts, which must match.
- The `predicateType` of each of your two attestations, read out of the verified payload rather than from this page.
- The decoded statement's `_type`, `subject` and `predicateType`, and where each came from: which values you supplied and which Cosign filled in.
- Three or four sentences: it is the morning after the next Log4Shell. You have two thousand images in your registry. What does this attestation let you do that a signature alone does not, and what still has to be true for that to work at three in the morning?

## Bonus — Sign the thing people curl (2 pts)

In 2021 Codecov's bash uploader was modified on their CDN and thousands of pipelines ran it with `curl | bash`. Nothing verified it. `cosign sign-blob` is the missing step.

<!-- verify:skip needs the key pair from 8.2 -->
```bash
printf '#!/bin/bash\necho "installing my-tool"\n' > /tmp/install.sh
tar -czf labs/lab8/results/my-tool.tar.gz -C /tmp install.sh

COSIGN_PASSWORD="<your passphrase>" cosign sign-blob \
  --key labs/lab8/keys/cosign.key --yes --tlog-upload=false \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle \
  labs/lab8/results/my-tool.tar.gz

cosign verify-blob --key labs/lab8/keys/cosign.pub \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle --insecure-ignore-tlog \
  labs/lab8/results/my-tool.tar.gz
```

Then play the attacker: change `/tmp/install.sh`, rebuild the tarball without re-signing, and verify again.

**Submit**, section `## Bonus`:

- `Verified OK` on the original, and the exact error on the modified tarball.
- The two files a consumer needs, and which of them may travel over the same channel as the artifact.
- Three or four sentences: Codecov's uploader was signed by nobody and verified by nobody. Write the install instructions you would publish so that a user who follows them cannot be given a modified script, and name the step most projects skip.

## Acceptance criteria

- Task 1 (6): the signed digest is the local-registry one; `cosign verify` succeeds on it; the tag is overwritten and verification of the new digest fails with the error quoted; the original digest still verifies; the explanation states what the signature binds to.
- Task 2 (4): both attestations attached and verified; the extracted SBOM has the same component count as Lab 4's; both `predicateType` values quoted from the payload; the statement fields explained by origin; the incident-response answer names a precondition, not just a benefit.
- Bonus (2): `Verified OK` before and a signature failure after modification, both quoted; the distribution answer identifies the key-distribution problem.
## Submit

<!-- verify:skip student fork files -->
```bash
git add <proof of work + lab8.md> (labs/lab8/keys/cosign.pub submissions/lab8.md, ...)
git commit -m "feat(lab8): cosign signing, tamper demo, sbom attestation"
git push -u origin feature/lab8
```

Never commit `cosign.key`. Clean up with `docker rm -f lab8-registry`.


## Common pitfalls

- Cosign **3.1.x** answers `--tlog-upload=false` with a `--signing-config` error. This lab is verified on 3.0.2; check `cosign version` first.
- `{{index .RepoDigests 0}}` gives the Docker Hub digest once the image has been pushed to a second registry. Filter for `localhost:5000/`, as 8.1 does.
- `cosign generate-key-pair` writes into the current directory, which is why 8.2 changes directory first.
- Forgetting `--allow-insecure-registry` against a plain-HTTP local registry gives a TLS error that reads like a network problem.
- `cosign verify` on an unsigned digest says `no signatures found`, which is the correct answer to "was this signed", not an error in your setup.
- The attestation payload is base64 inside JSON. `jq -r '.payload | @base64d | fromjson'` is how you read it.

## Resources

- [Cosign documentation](https://docs.sigstore.dev/cosign/signing/overview/) and [signing blobs](https://docs.sigstore.dev/cosign/signing/other_types/)
- [in-toto attestation specification](https://github.com/in-toto/attestation/blob/main/spec/README.md)
- [SLSA v1.0](https://slsa.dev/spec/v1.0/) — where attestations fit in a build's provenance
- [Codecov's own account of the 2021 incident](https://about.codecov.io/security-update/)
