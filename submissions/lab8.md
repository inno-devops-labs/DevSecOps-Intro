# \# Lab 8 — Submission

# 

# \## Task 1: Sign and Verify a Container Image

# 

# \### Local registry + push

# 

# &#x20;   docker run -d --name lab8-registry -p 127.0.0.1:5000:5000 registry:3

# &#x20;   docker pull bkimminich/juice-shop:v20.0.0

# &#x20;   docker tag bkimminich/juice-shop:v20.0.0 localhost:5000/juice-shop:v20.0.0

# &#x20;   docker push localhost:5000/juice-shop:v20.0.0

# 

# Digest:

# 

# &#x20;   localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe

# 

# Note: `docker inspect --format "{{index .RepoDigests 0}}"` returned the wrong

# digest (the original Docker Hub digest, not the local-registry one), because

# the image had two RepoDigests entries and index 0 picked the wrong one. Used

# the digest from `docker push` output instead, cross-checked with

# `docker manifest inspect --insecure -v`.

# 

# \### Keypair + sign + verify

# 

# &#x20;   cosign generate-key-pair

# &#x20;   cosign sign --key labs/lab8/keys/cosign.key --yes --allow-http-registry <digest>

# &#x20;   cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog --allow-http-registry <digest>

# 

# Result: verification succeeded.

# 

# &#x20;   Verification for localhost:5000/juice-shop@sha256:28870b9d... --

# &#x20;   The following checks were performed on each of these signatures:

# &#x20;     - The cosign claims were validated

# &#x20;     - Existence of the claims in the transparency log was verified offline

# &#x20;     - The signatures were verified against the specified public key

# 

# Full output: `labs/lab8/results/verify-original.json`.

# 

# \### Tamper demonstration

# 

# Pushed `alpine:3.20` under the same repo as `juice-shop:v20.0.0-tampered` to

# show a signature is bound to a digest, not a tag.

# 

# Tampered digest: `sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e`

# 

# &#x20;   cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog --allow-http-registry <tampered-digest>

# 

# Result: verification correctly failed.

# 

# &#x20;   Error: no signatures found

# 

# Full output: `labs/lab8/results/verify-tampered.txt`. Re-verified the original

# digest afterward — still succeeded, confirming the original signature was

# unaffected by the tampered push.

# 

# \## Task 2: SBOM Attestation

# 

# `labs/lab4/juice-shop.cdx.json` was missing locally (not preserved from Lab

# 4), so it was regenerated with Trivy in CycloneDX format before this task:

# 

# &#x20;   trivy image --format cyclonedx --output labs/lab4/juice-shop.cdx.json bkimminich/juice-shop:v20.0.0

# 

# Confirmed non-empty: 905 components.

# 

# \### Attest + verify

# 

# &#x20;   cosign attest --key labs/lab8/keys/cosign.key --type cyclonedx \\

# &#x20;     --predicate labs/lab4/juice-shop.cdx.json --allow-http-registry --yes <digest>

# 

# &#x20;   cosign verify-attestation --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \\

# &#x20;     --allow-http-registry --type cyclonedx <digest>

# 

# Result: verification succeeded (same three checks as image verify above).

# 

# \### Extract and compare

# 

# Decoded the base64 in-toto payload and pulled `.predicate` back out to

# `labs/lab8/results/sbom-from-attestation.json`:

# 

# &#x20;   jq '.components | length' labs/lab8/results/sbom-from-attestation.json

# &#x20;   905

# 

# Matches the source SBOM component count exactly — the attestation round-trips

# the SBOM without loss, so anyone with the public key can pull a verified SBOM

# straight off the image instead of trusting a separately-distributed file.

# 

# \## Bonus: Blob Signing

# 

# Signed a plain text file (not an image) to demonstrate Cosign outside OCI

# registries:

# 

# &#x20;   cosign sign-blob --key labs/lab8/keys/cosign.key --yes \\

# &#x20;     --bundle labs/lab8/results/release-notes.bundle.json \\

# &#x20;     labs/lab8/results/release-notes.txt

# 

# Note: `--output-signature` is deprecated in Cosign v3; `--bundle` produces a

# single JSON bundle with the signature instead of a separate `.sig` file.

# 

# \### Verify (original vs tampered)

# 

# &#x20;   cosign verify-blob --key labs/lab8/keys/cosign.pub --bundle labs/lab8/results/release-notes.bundle.json \\

# &#x20;     --insecure-ignore-tlog labs/lab8/results/release-notes.txt

# &#x20;   Verified OK

# 

# &#x20;   cosign verify-blob --key labs/lab8/keys/cosign.pub --bundle labs/lab8/results/release-notes.bundle.json \\

# &#x20;     --insecure-ignore-tlog labs/lab8/results/release-notes-tampered.txt

# &#x20;   Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature

# 

# Blob signing behaves the same as image signing: any change to the signed

# content invalidates the signature.

# 

# \## Environment notes / issues encountered

# 

# \- Cosign installed via winget as `cosign-windows-amd64.exe`, not `cosign` —

# &#x20; resolved with a session-scoped `Set-Alias`.

# \- Cosign v3.1.1 (course pins v2.4.x) needed two extra flags not in the

# &#x20; original instructions: `--allow-http-registry` for the plain-HTTP local

# &#x20; registry, and `--bundle` instead of the deprecated `--output-signature` for

# &#x20; blob signing.

# \- No `.pre-commit-config.yaml` is installed in this repo, so the Lab 3

# &#x20; gitleaks hook didn't run when testing that `cosign.key` gets blocked from

# &#x20; commits. `.gitignore` caught it independently — `git add` refused the file

# &#x20; without `-f`.

# 

# \## Results directory

# 

# &#x20;   labs/lab8/

# &#x20;   ├── keys/

# &#x20;   │   ├── cosign.key          (gitignored, not committed)

# &#x20;   │   └── cosign.pub

# &#x20;   └── results/

# &#x20;       ├── juice-shop-digest.txt

# &#x20;       ├── verify-original.json

# &#x20;       ├── verify-tampered.txt

# &#x20;       ├── sbom-from-attestation.json

# &#x20;       ├── release-notes.txt

# &#x20;       ├── release-notes.bundle.json

# &#x20;       └── release-notes-tampered.txt

