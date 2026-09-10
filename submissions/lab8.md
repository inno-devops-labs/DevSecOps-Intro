# Lab 8 — Supply Chain Signing

## Task 1

### Digest signed
`localhost:5000/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d`

Picked with:
```bash
docker inspect localhost:5000/juice-shop:v20.0.0 \
  --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep '^localhost:5000/'
```
(not the Docker Hub digest).

### Successful verify
```
Verification for localhost:5000/juice-shop@sha256:45e09956... --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:45e09956..."},
"image":{"docker-manifest-digest":"sha256:45e09956..."},
"type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

### Tamper
Overwrote tag `v20.0.0` with `alpine:3.20` → digest became `sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`.

```
Error: no signatures found
```

Original digest still verifies afterwards.

### Bound to digest, not tag
The signature is over the **manifest digest**. Renaming the tag to point at Alpine does not move the signature; Cosign correctly says the new digest has no signature. If signatures were bound to tags, an attacker could overwrite `v20.0.0` and keep a “valid” tag-level claim — exactly this swap would succeed.

Public key committed: `labs/lab8/keys/cosign.pub` (private key gitignored / never committed).

## Task 2 / Bonus

_(Attestation + blob signing — complete after Lab 4 SBOM is on this branch; Cosign 3.0.2 at `tools/bin/cosign`.)_

Commands prepared:
```bash
COSIGN_PASSWORD=lab8pass cosign attest --key labs/lab8/keys/cosign.key \
  --type cyclonedx --predicate labs/lab4/juice-shop.cdx.json \
  --tlog-upload=false --allow-insecure-registry --yes "$DIGEST_REF"
```
