# Lab 8 — Submission

## Environment

- Local registry: `localhost:5001`
- Registry container: `lab8-registry`
- Image: `bkimminich/juice-shop:v20.0.0`
- Local registry image: `localhost:5001/juice-shop:v20.0.0`
- Cosign version: `v3.1.1`
- Signing mode: keyed signing with local Cosign keypair
- Private key: `labs/lab8/keys/cosign.key` ignored by git
- Public key: `labs/lab8/keys/cosign.pub`

Note: The lab template uses `localhost:5000`, but on my macOS machine port `5000` was already handled by an Apple service (`AirTunes`) and returned `403 Forbidden`. Because of that, I used `localhost:5001` for the local registry. The supply-chain flow is the same.

---

## Task 1: Sign + Tamper Demo

### Registry + image push

- Registry container: `lab8-registry`
- Registry endpoint: `localhost:5001`
- Image pushed: `localhost:5001/juice-shop:v20.0.0`
- Image digest:

```text
localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

The image was pushed to the local Distribution registry. Docker push reported the local registry digest:

```text
v20.0.0: digest: sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113 size: 4847
```

### Signing

Command used:

```bash
COSIGN_PASSWORD="$LAB8_COSIGN_PASSWORD" cosign sign \
  --key labs/lab8/keys/cosign.key \
  --use-signing-config=false \
  --allow-http-registry \
  --yes \
  "localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
```

Relevant output:

```text
Signing artifact...
Pushing signature to: localhost:5001/juice-shop
```

### Verification: original digest passed

Command used:

```bash
cosign verify \
  --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog \
  --allow-http-registry \
  "localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
```

Output:

```json
[{"critical":{"identity":{"docker-reference":"localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper demo: failed correctly

For the tamper demo, I pulled `alpine:3.20`, tagged it as a fake Juice Shop image, and pushed it to the same local registry under a different tag.

Tampered image digest:

```text
localhost:5001/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
```

The tampered digest is different from the original Juice Shop digest:

```text
Original:
localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113

Tampered:
localhost:5001/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
```

Verification of the tampered digest failed correctly:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity check: original still verifies

After the tamper attempt, the original digest still verified successfully:

```json
[{"critical":{"identity":{"docker-reference":"localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters

Cosign signs the immutable image digest, not only the mutable tag. In the tamper demo, the fake image reused the `juice-shop` repository name but pointed to a completely different digest. Because the signature was bound to the original digest, Cosign refused to verify the tampered image.

If Cosign signed only the tag, an attacker could replace the tag with a malicious image and still make it look like the same application version. Digest binding prevents this tag-mutation attack because any content change produces a different digest and requires a new valid signature.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

The CycloneDX SBOM from Lab 4 was used as the attestation predicate:

```text
labs/lab4/juice-shop.cdx.json
```

SBOM metadata:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "component_count": 3068
}
```

Command used:

```bash
COSIGN_PASSWORD="$LAB8_COSIGN_PASSWORD" cosign attest \
  --key labs/lab8/keys/cosign.key \
  --type cyclonedx \
  --predicate labs/lab4/juice-shop.cdx.json \
  --use-signing-config=false \
  --allow-http-registry \
  --yes \
  "localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
```

Relevant output:

```text
Using payload from: labs/lab4/juice-shop.cdx.json
Signing artifact...
```

The SBOM attestation was verified and decoded. Decoded attestation sample:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "localhost:5001/juice-shop",
      "digest": {
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      }
    }
  ],
  "predicate_component_count": 3068
}
```

Component count comparison:

```text
Source SBOM components:
3068

SBOM from attestation:
3068
```

Diff result:

```text
OK: SBOM from attestation matches Lab 4 SBOM
```

This confirms that the SBOM extracted from the Cosign attestation matches the Lab 4 CycloneDX SBOM.

### Provenance attestation

A minimal SLSA provenance predicate was attached to the same image digest.

Builder ID:

```text
https://localhost/lab8-student
```

Build type:

```text
https://example.com/lab8/local-registry-signing
```

Decoded provenance predicate:

```json
{
  "buildType": "https://example.com/lab8/local-registry-signing",
  "builder": {
    "id": "https://localhost/lab8-student"
  },
  "invocation": {
    "configSource": {
      "digest": {
        "sha1": "8b88dd08b1419119830eea38f3532aa323386743"
      },
      "uri": "git@github.com:Esqavator/DevSecOps-Intro.git"
    }
  },
  "materials": [
    {
      "digest": {
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      },
      "uri": "localhost:5001/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
    }
  ]
}
```

The provenance attestation verification succeeded with Cosign using the public key.

### What this gives a Lab 9 verifier

At Kubernetes admission time, a policy such as Kyverno `verifyImages` can require both a valid image signature and specific attestations. A signed image without an SBOM only proves that the image digest was signed by the expected key. A signed image with an SBOM also gives the cluster or security pipeline a machine-readable dependency inventory.

Operationally, this matters during a Log4Shell-style incident. If a new critical vulnerability appears in a library, the SBOM attestation lets the verifier or scanner quickly determine whether the signed image contains the affected component. Without the SBOM, the image may be signed, but the organization still lacks a reliable dependency inventory for incident response.

---

## Bonus: Blob Signing — Codecov 2021 Mitigation

### Sign + verify

A small release artifact was created:

```text
labs/lab8/results/my-tool.tar.gz
```

The blob was signed with Cosign v3 bundle format:

```bash
COSIGN_PASSWORD="$LAB8_COSIGN_PASSWORD" cosign sign-blob \
  --key labs/lab8/keys/cosign.key \
  --use-signing-config=false \
  --yes \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle \
  labs/lab8/results/my-tool.tar.gz
```

Relevant output:

```text
Using payload from: labs/lab8/results/my-tool.tar.gz
Signing artifact...
Wrote bundle to file labs/lab8/results/my-tool.tar.gz.bundle
```

Verification command:

```bash
cosign verify-blob \
  --key labs/lab8/keys/cosign.pub \
  --bundle labs/lab8/results/my-tool.tar.gz.bundle \
  --insecure-ignore-tlog \
  labs/lab8/results/my-tool.tar.gz
```

Verification output:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed correctly

The tarball was modified after signing by appending malicious content:

```bash
echo "MALICIOUS PAYLOAD" >> /tmp/fresh-download/my-tool.tar.gz
```

Verification of the tampered blob failed:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation

The Codecov bash uploader attack class relied on users downloading and executing a script without verifying that the bytes were authentic. If CI consumers had required a signature check before execution, the modified uploader would not have matched the original signed byte stream.

The protective pattern would be:

```bash
cosign verify-blob \
  --key cosign.pub \
  --bundle uploader.bundle \
  uploader.sh
```

Only after `cosign verify-blob` returned `Verified OK` should the script be executed. In this lab, the tampered tarball failed verification after a single byte-level content change, which is the same kind of protection that would stop a modified installer or uploader from being trusted.
