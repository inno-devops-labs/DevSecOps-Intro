# Lab 8 — Submission

> Tooling: Cosign v3.1.1, jq. Keypair generated locally (`labs/lab8/keys/`, `cosign.key` gitignored).

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` on `localhost:5000` (`registry:3`)
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Registry digest (authoritative, from `Docker-Content-Digest`):
  `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`

> Cosign v3 note: `--tlog-upload=false` now requires `--use-signing-config=false` (v3 defaults to a
> Sigstore signing-config with a transparency log). Keyed offline signing to a local HTTP registry:
> `cosign sign --key cosign.key --use-signing-config=false --tlog-upload=false --allow-insecure-registry`.

### Signing
```
Signing artifact...
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)
`cosign verify --key cosign.pub --insecure-ignore-tlog` on the original digest:
```
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec... --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```
(exit 0.)

### Tamper Demo (FAILED — correctly)
Re-tagged `alpine:3.20` as `localhost:5000/juice-shop:v20.0.0-tampered` and pushed. Its digest is
different (`sha256:d9e853e8…`), so `cosign verify` on it:
```
Error: no signatures found
```
(exit 10 — no signature exists for the alpine digest.)

### Sanity — original still verifies
Re-running `cosign verify` on the original `sha256:28870b9d…` digest → **exit 0** (still valid).
The signature is bound to the digest, not the tag.

### Why digest binding matters
The tamper attempt swapped the *content* (alpine) behind a juice-shop-looking tag, producing a
**different digest**. Because the signature was bound to the original digest, the swap is simply
"unsigned" — verification finds no signature and fails closed. Had Cosign signed the mutable **tag**
`:v20.0.0` instead, an attacker who re-points that tag to malicious content would inherit a tag that
still "has a signature", and only a careful digest comparison would catch it — exactly the
tag-mutation attack digest-pinning defeats (Lecture 8 slide 6).

## Task 2: SBOM + Provenance Attestations

### SBOM attestation (CycloneDX)
`cosign attest --type cyclonedx --predicate labs/lab4/juice-shop.cdx.json` → exit 0.
`cosign verify-attestation --type cyclonedx` → exit 0. Decoded in-toto statement:
```
_type:          https://in-toto.io/Statement/v0.1
predicateType:  https://cyclonedx.org/bom
subject:        localhost:5000/juice-shop @ sha256:28870b9d2bec...
predicate.components: 1846
```
- Component count matches Lab 4 source: **yes — 1846 == 1846** ✅ (decoded predicate vs
  `labs/lab4/juice-shop.cdx.json`).

### Provenance attestation (SLSA)
`cosign attest --type slsaprovenance --predicate <predicate>` → exit 0.
`cosign verify-attestation --type slsaprovenance` → exit 0. Decoded:
```
predicateType:  https://slsa.dev/provenance/v0.2
builder.id:     https://localhost/lab8-student
buildType:      https://example.com/lab8/local-build
```

### What this gives a Lab 9 verifier
A "signed but no SBOM" image proves *who built it*; a "signed **with** SBOM" image also proves
*what's inside it* — cryptographically bound to that exact digest. When the next Log4Shell drops, a
Kyverno `verifyImages` policy at admission can require both the signature **and** a CycloneDX
attestation, and a verifier can pull the attested SBOM straight off the running image's digest and
answer "do we ship the vulnerable library?" in seconds — without re-scanning or trusting a
side-channel SBOM that might not match the deployed bits (Lecture 8 slide 12 + Lecture 9 slide 4).

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

Fully completed — pure Cosign, no registry needed.

### Sign + verify
Signed `my-tool.tar.gz` → produced `my-tool.tar.gz.bundle` (`cosign sign-blob --bundle`).
`cosign verify-blob` on the original artifact:
```
WARNING: Skipping tlog verification is an insecure practice ...
Verified OK
```
(exit 0 — signature valid.)

### Tamper test failed (correctly)
Appended `MALICIOUS PAYLOAD` to a copy of the tarball, then re-ran `cosign verify-blob` with the
same bundle:
```
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: ...
```
(exit 1 — the signature is bound to the original byte stream, so any modification is rejected.)

### Codecov 2021 mitigation
Codecov's Bash Uploader was distributed via `curl … | bash` with **no verification**, so when
attackers altered the hosted script (exfiltrating CI secrets) every consumer silently ran the
malicious version. Had Codecov published a signature and had consumers run
`cosign verify-blob --key codecov.pub --bundle uploader.sig uploader.sh` **before** executing it,
the altered script's bytes would no longer match the signature — `verify-blob` exits non-zero and
the `bash` step never runs (Lecture 8 slide 14). Signing the artifact turns a silent supply-chain
compromise into a hard CI failure at the point of consumption.
