# Lab 8 - Submission

## Task 1: Sign + Tamper Demo

### Registry + image push

- Registry container: `lab8-registry` running on `localhost:5000`
- Registry image: `registry:3`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest:

```text
localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```

The digest was resolved from the local registry API after the push. Docker pushed a single-platform manifest to the local registry, so its registry digest differs from the original multi-platform Docker Hub digest.

### Signing

The image was signed by digest with the generated Cosign private key:

```text
Signing: localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
Pushing signature to: localhost:5000/juice-shop
```

The private key is stored at `labs/lab8/keys/cosign.key` and is excluded by the repository's `*.key` rule. Only the public key at `labs/lab8/keys/cosign.pub` is intended for the commit.

### Verification (PASSED)

Command:

```bash
cosign verify \
  --key labs/lab8/keys/cosign.pub \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  "localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
```

Output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.

Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

Verification claims:

```json
[
  {
    "critical": {
      "identity": {
        "docker-reference": "localhost:5000/juice-shop"
      },
      "image": {
        "docker-manifest-digest": "sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      },
      "type": "cosign container image signature"
    },
    "optional": null
  }
]
```

Exit code:

```text
0
```

### Tamper Demo (FAILED - correctly)

A different image, `alpine:3.20`, was pushed under the similar-looking tag:

```text
localhost:5000/juice-shop:v20.0.0-tampered
```

Original digest:

```text
localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```

Tampered digest:

```text
localhost:5000/juice-shop@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
```

Output of `cosign verify` on the tampered digest:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

Exit code:

```text
10
```

The failure is expected because no signature exists for the Alpine manifest digest.

### Sanity - original still verifies

After the tampered image was pushed, the original digest was verified again:

```text
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"cosign container image signature"},"optional":null}]
```

Exit code:

```text
0
```

### Why digest binding matters

An OCI tag is a mutable pointer and can be changed to reference a different manifest without changing the visible repository name. Cosign signs the immutable manifest digest, so replacing or re-tagging the image changes the digest and causes signature verification to fail.

If Cosign signed only the tag name, an attacker could move the signed-looking tag to malicious content while preserving the same human-readable image reference. Digest binding prevents that substitution because the signature remains valid only for the exact bytes represented by the original digest.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

- Attached: yes
- Attestation type: `cyclonedx`
- Command exit code: `0`
- Source SBOM: `labs/lab4/juice-shop.cdx.json`
- Source SBOM format: CycloneDX 1.6

Command:

```bash
cosign attest \
  --key labs/lab8/keys/cosign.key \
  --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json \
  --allow-insecure-registry \
  --tlog-upload=false \
  --yes \
  "$DIGEST"
```

Output:

```text
Using payload from: labs/lab4/juice-shop.cdx.json
```

Verify-attestation output, decoded payload excerpt:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      }
    }
  ],
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
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

Component counts:

```text
Source:    1846
Extracted: 1846
```

Component count matches Lab 4 source: **yes**

Diff command:

```bash
diff \
  <(jq -S '.components | length' labs/lab4/juice-shop.cdx.json) \
  <(jq -S '.components | length' labs/lab8/results/sbom-from-attestation.json)
```

Diff output:

```text
```

The diff was empty and returned exit code `0`, which confirms that both documents contain the same number of components.

### Provenance attestation

- Attached: yes
- Attestation type: `slsaprovenance`
- Command exit code: `0`
- Builder ID: `https://localhost/lab8-student`
- Build type: `https://example.com/lab8/local-build`
- Source repository: `https://github.com/m1d0rfeed/DevSecOps-Intro`
- Source commit: `f9932471eb75787a0588c96ee2fc4f65ed0772e8`

Predicate body:

```json
{
  "builder": {
    "id": "https://localhost/lab8-student"
  },
  "buildType": "https://example.com/lab8/local-build",
  "invocation": {
    "configSource": {
      "uri": "https://github.com/m1d0rfeed/DevSecOps-Intro",
      "digest": {
        "sha1": "f9932471eb75787a0588c96ee2fc4f65ed0772e8"
      }
    }
  }
}
```

Verification output:

```text
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

Decoded provenance predicate:

```json
{
  "builder": {
    "id": "https://localhost/lab8-student"
  },
  "buildType": "https://example.com/lab8/local-build",
  "invocation": {
    "configSource": {
      "uri": "https://github.com/m1d0rfeed/DevSecOps-Intro",
      "digest": {
        "sha1": "f9932471eb75787a0588c96ee2fc4f65ed0772e8"
      }
    }
  }
}
```

### What this gives a Lab 9 verifier

A valid image signature proves that the image has not changed since it was signed, but it does not describe the software components inside the image. An attached and verified SBOM gives an admission controller or security workflow a signed inventory that can be checked against vulnerability and policy requirements.

When a vulnerability such as Log4Shell is announced, a signed image without an SBOM still requires rescanning or manual investigation to determine whether the affected dependency is present. A signed image with a verified SBOM can be evaluated immediately by matching the vulnerable component and version against the attested inventory, while a Kyverno `verifyImages` policy can require both the signature and the expected attestation predicate before admission.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Release artifact

A test installer was packaged into a tarball:

```bash
cat > /tmp/install.sh <<'EOF'
#!/bin/bash
echo "Welcome to my-cool-tool installer"
echo "Running setup..."
EOF

chmod +x /tmp/install.sh
tar -czf labs/lab8/results/my-tool.tar.gz -C /tmp install.sh
```

Archive contents:

```text
install.sh
```

### Sign + verify

Signed files:

```text
my-tool.tar.gz
my-tool.tar.gz.bundle
```

Signing command:

```bash
cosign sign-blob \
  --key labs/lab8/keys/cosign.key \
  --yes \
  --tlog-upload=false \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle \
  labs/lab8/results/my-tool.tar.gz
```

Signing output:

```text
Using payload from: labs/lab8/results/my-tool.tar.gz
Wrote bundle to file labs/lab8/results/my-tool.tar.gz.bundle
```

Verification command:

```bash
cosign verify-blob \
  --key cosign.pub \
  --bundle my-tool.tar.gz.bundle \
  --insecure-ignore-tlog \
  my-tool.tar.gz
```

Verify-blob success output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Verified OK
```

Exit code:

```text
0
```

### Tamper test failed (correctly)

The downloaded archive was modified after it had been signed:

```bash
echo "MALICIOUS PAYLOAD" >> my-tool.tar.gz
```

Verification output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the blob.
Error: invalid signature when validating ASN.1 encoded signature
error during command execution: invalid signature when validating ASN.1 encoded signature
```

Exit code:

```text
1
```

### Codecov 2021 mitigation

The Codecov Bash uploader was consumed by CI environments without cryptographic verification, so a modified uploader could execute while still being downloaded from an expected location. If consumers had downloaded the uploader together with a trusted Cosign public key and signature bundle, they could have run `cosign verify-blob` before executing the script.

A maliciously modified uploader would no longer match the signed byte stream, producing an invalid-signature error like the tamper test above. The CI job could then stop before running `bash`, preventing the altered script from accessing environment variables, credentials, and other secrets available to the build process.