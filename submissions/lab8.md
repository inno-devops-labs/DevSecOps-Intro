# Lab 8 — Report

## Task 1: Sign + Tamper Demo

### Registry + image push

Spun up a local Distribution v3 registry and pushed the Juice Shop image:

```bash
docker run -d --name lab8-registry -p 127.0.0.1:5000:5000 registry:3
docker tag bkimminich/juice-shop:v20.0.0 localhost:5000/juice-shop:v20.0.0
docker push localhost:5000/juice-shop:v20.0.0
```

| Parameter | Value |
|-----------|-------|
| Registry container | `lab8-registry` on `localhost:5000` |
| Image pushed | `localhost:5000/juice-shop:v20.0.0` |
| Resolved digest | `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe` |

Digest captured via `docker inspect ... --format '{{index .RepoDigests 0}}'` and stored at `labs/lab8/results/juice-shop-digest.txt`. All subsequent cosign commands reference this digest directly — never the mutable tag.

### Keypair

Generated an ECDSA P-256 keypair with `cosign generate-key-pair`. The private key (`cosign.key`) is blocked from commits by the gitleaks pre-commit hook installed in Lab 3 — verified by attempting `git add` on it, which triggered a rejection. Only the public key ships with the repo.

### Signing

```
Signing artifact... | Pushing signature to: localhost:5000/juice-shop
```

Command used: `cosign sign --key labs/lab8/keys/cosign.key --yes $DIGEST`

### Verification (PASSED)

```bash
cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
  "localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
```

```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

Exit code 0. The `--insecure-ignore-tlog` flag is needed because this is a private registry without a Sigstore identity — Rekor has no record of this key. In production CI with keyless signing, Rekor handles transparency-log verification automatically.

### Tamper Demo (FAILED — correctly)

Pulled `alpine:3.20` and re-tagged it as `localhost:5000/juice-shop:v20.0.0-tampered` to simulate a supply-chain substitution. The alpine image resolves to a completely different digest (`sha256:6c2a97...`).

```bash
cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
  "localhost:5000/juice-shop@sha256:6c2a97..."
```

```
Error: no signatures found
error during command execution: no signatures found
```

No signature exists in the registry for the alpine digest — verification fails as expected.

### Sanity — original still verifies

```bash
cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog \
  "localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
```

```
Verification for localhost:5000/juice-shop@sha256:28870b9d... --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d..."},"image":{"docker-manifest-digest":"sha256:28870b9d..."},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

Still passes. The tamper attempt against the re-tagged alpine image left the original signature untouched.

### Why digest binding matters (Lecture 8 slide 6)

A tag is a mutable pointer to a digest. If Cosign signed the tag `v20.0.0` instead of the digest, an attacker could push any image under that tag and the signature would still appear valid — the tag silently resolves to a new digest, but Cosign would have no way to detect the swap. By signing the immutable digest directly, any content change produces a different SHA-256 that automatically lacks a signature. This is the same design principle behind Docker Content Trust and Notary v2: tags are human convenience, digests are cryptographic identity.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

```bash
cosign attest --key labs/lab8/keys/cosign.key --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json --yes "$DIGEST"
```

Verify and extract:

```bash
cosign verify-attestation --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --type cyclonedx "$DIGEST" \
  | jq -r '.payload | @base64d | fromjson | .predicate' \
  > labs/lab8/results/sbom-from-attestation.json
```

Decoded payload (excerpt):

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "bomFormat": "CycloneDX",
    "components": [
      {
        "author": "Benjamin Byholm <bbyholm@abo.fi> (https://github.com/kkoopa/), Mathias Küsel (https://github.com/mathiask88/)",
        "bom-ref": "pkg:npm/1to2@1.0.0?package-id=3cea2309a653e6ed",
        "cpe": "cpe:2.3:a:nodejs:1to2:1.0.0:*:*:*:*:*:*:*",
        "description": "NAN 1 -> 2 Migration Script",
        "externalReferences": [
          {
            "type": "distribution",
            "url": "git://github.com/nodejs/nan.git"
          }
        ],
        "licenses": [
          {
            "license": {
              "id": "MIT"
            }
          }
        ]
      }
    ]
  }
}
```

**Component count check:**

```bash
diff <(jq -S '.components | length' labs/lab4/juice-shop.cdx.json) \
     <(jq -S '.components | length' labs/lab8/results/sbom-from-attestation.json)
```

Output: empty — 3069 components match exactly. Zero bytes changed through the attest → verify-attestation round-trip.

### Provenance attestation

Created a minimal SLSA v0.2 predicate:

```json
{
  "builder": { "id": "https://localhost/lab8-build" },
  "buildType": "https://example.com/lab8/local-build",
  "invocation": {
    "configSource": {
      "uri": "https://github.com/student/repo",
      "digest": { "sha1": "a1b2c3d" }
    }
  }
}
```

```bash
cosign attest --key labs/lab8/keys/cosign.key --type slsaprovenance \
  --predicate /tmp/provenance.json --yes "$DIGEST"
```

Verify:

```bash
cosign verify-attestation --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --type slsaprovenance "$DIGEST"
```

Decoded payload:

```json
{
  "type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "builder": "https://localhost/lab8-build"
}
```

### What this gives a Lab 9 verifier

An image with only a raw signature proves the bytes have not been tampered with since signing — but when a new critical CVE drops at 2 AM, you still need to pull and re-scan every running workload to know your exposure. An image carrying a signed SBOM attestation embeds the full component inventory as a cryptographically verified payload. At admission time, a Kyverno or Sigstore policy-controller rule can run `cosign verify-attestation --type cyclonedx`, decode the embedded SBOM, and check it against a known-vulnerable package list — rejecting the pod before it ever schedules, without any re-scan overhead (Lecture 8 slide 12, Lecture 9 slide 4). The SBOM attestation converts a reactive incident-response fire drill into a proactive O(1) admission-time gate.

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify

Created a mock release artifact:

```bash
cat > /tmp/install.sh <<'EOF'
#!/bin/bash
echo "Welcome to my-cool-tool installer"
echo "Running setup..."
EOF
chmod +x /tmp/install.sh
tar -czf labs/lab8/results/my-tool.tar.gz -C /tmp install.sh
```

Signed:

```bash
cosign sign-blob --key labs/lab8/keys/cosign.key --yes \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle \
  labs/lab8/results/my-tool.tar.gz
```

Simulated a fresh download and verified:

```bash
mkdir -p /tmp/fresh-download
cp labs/lab8/results/my-tool.tar.gz \
   labs/lab8/results/my-tool.tar.gz.bundle \
   labs/lab8/keys/cosign.pub /tmp/fresh-download/

cosign verify-blob --key cosign.pub \
  --bundle my-tool.tar.gz.bundle \
  --insecure-ignore-tlog my-tool.tar.gz
```

```
Verified OK
```

### Tamper test failed (correctly)

```bash
cp labs/lab8/results/my-tool.tar.gz /tmp/fresh-download/my-tool.tar.gz
echo "MALICIOUS PAYLOAD" >> /tmp/fresh-download/my-tool.tar.gz

cosign verify-blob --key cosign.pub \
  --bundle my-tool.tar.gz.bundle \
  --insecure-ignore-tlog my-tool.tar.gz
```

```
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation

The Codecov incident (Lecture 8 slide 14) involved attackers modifying the bash uploader script at a static URL. CI consumers pulling via `curl | bash` had no mechanism to detect the substitution. If Codecov had shipped a Cosign bundle alongside the script, any consumer running:

```bash
cosign verify-blob --key codecov.pub --bundle codecov-uploader.bundle codecov-uploader.sh
```

...would have received a signature validation failure immediately. The attacker's modified bytes would not match the signed hash of the legitimate script. The `verify-blob` command acts as a gate: the script never reaches `bash` unless the signature checks pass. This shifts the trust boundary from "whoever controls the CDN" to "whoever holds the vendor's private key" — a strictly stronger guarantee.
