# Lab 8 Submission - Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 - Local Registry, Signing, Verification, and Tamper Demo

### 1.1 Image push to local registry and digest pinning

Commands used:

```bash
docker run -d --restart=always -p 5000:5000 --name registry registry:3
docker tag bkimminich/juice-shop:v19.0.0 localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

Digest reference recorded in:
- `labs/lab8/analysis/ref.txt`

Result:

```text
Using digest ref: localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48
```

Why digest and not tag:
- Tag is mutable (`v19.0.0` can be overwritten).
- Digest is content-addressed; if content changes, digest changes.
- Cosign signatures are bound to digest, not tag.

### 1.2 Cosign key pair generation

Command used:

```bash
cosign generate-key-pair
```

Generated files in `labs/lab8/signing/`:
- `cosign.key` (private key, local only, not for commit)
- `cosign.pub` (public key, used for verification)

### 1.3 Sign and verify

Commands used:

```bash
cosign sign --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  "$REF"

cosign verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "$REF"
```

Verification output saved in:
- `labs/lab8/signing/verify-output.txt`

Verification succeeded for digest:
- `sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48`

### 1.4 Tamper demonstration

Tamper actions:

```bash
docker tag busybox:latest localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

Tampered digest recorded in:
- `labs/lab8/analysis/ref-after-tamper.txt`

Result:

```text
After tamper digest ref: localhost:5000/juice-shop@sha256:11f85134f388cff5f4c66f9bb4c5942249c1f6f7eb8b3889948d953487b5f7a8
```

Tamper verification evidence:
- `labs/lab8/signing/tamper-demo-output.txt`

Observed behavior:
- Verify tampered digest: failed (`no signatures found`, exit code 10).
- Verify original signed digest: succeeded (exit code 0).

### 1.5 Analysis: subject digest and protection against tag tampering

Subject digest is the manifest digest (`sha256:...`) that the signature covers.  
When a tag is overwritten with different content:
- new content => new digest
- existing signature does not match new digest
- verification fails for tampered digest, but still succeeds for the original signed digest

This is exactly what was observed in `tamper-demo-output.txt`.

---

## Task 2 - Attestations (SBOM and Provenance)

### 2.1 SBOM (CycloneDX) attestation

SBOM conversion command:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab4/syft:/in:ro" \
  -v "$(pwd)/labs/lab8/attest:/out" \
  anchore/syft:latest \
  convert /in/juice-shop-syft-native.json -o cyclonedx-json=/out/juice-shop.cdx.json
```

Attest + verify commands:

```bash
cosign attest --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "$REF"

cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type cyclonedx \
  "$REF"
```

Saved evidence:
- raw verify output: `labs/lab8/attest/verify-sbom-attestation.txt`
- decoded in-toto statement: `labs/lab8/attest/verify-sbom-attestation-decoded.json`

Payload inspection with jq:

```bash
jq '.predicate.components | length' labs/lab8/attest/verify-sbom-attestation-decoded.json
```

Result:
- `3533` components

Key decoded fields:
- `_type`: `https://in-toto.io/Statement/v0.1`
- `predicateType`: `https://cyclonedx.org/bom`
- `subject.digest.sha256`: `b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48`
- `predicate.bomFormat`: `CycloneDX`
- `predicate.specVersion`: `1.6`

What SBOM attestation contains:
- cryptographic binding to exact image digest (`subject`)
- SBOM metadata (tool, timestamp, component info)
- full package inventory (`components`)

### 2.2 Provenance attestation

Predicate file:
- `labs/lab8/attest/provenance.json`

Attest + verify commands:

```bash
cosign attest --yes \
  --allow-insecure-registry \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/provenance.json \
  --type slsaprovenance \
  "$REF"

cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type slsaprovenance \
  "$REF"
```

Saved evidence:
- raw verify output: `labs/lab8/attest/verify-provenance.txt`
- decoded in-toto statement: `labs/lab8/attest/verify-provenance-decoded.json`

Decoded provenance fields:
- `_type`: `https://in-toto.io/Statement/v0.1`
- `predicateType`: `https://slsa.dev/provenance/v0.2`
- `subject.digest.sha256`: `b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48`
- `predicate.builder.id`: `student@local`
- `predicate.buildType`: `manual-local-demo`
- `predicate.metadata.buildStartedOn`: `2026-03-30T14:53:49Z`
- `predicate.invocation.parameters.image`: pinned digest reference

### 2.3 Analysis: signatures vs attestations

Signature:
- proves the image digest is signed by trusted key
- used for binary trust decision

Attestation:
- signed statement with typed metadata (SBOM/provenance)
- enables policy decisions beyond simple signature existence

Supply-chain value of provenance:
- links artifact digest to builder identity and build context
- improves auditability and incident investigation
- enables admission/policy checks on build origin and metadata

---

## Task 3 - Artifact (Blob/Tarball) Signing

Commands used:

```bash
echo "sample content $(date -u)" > labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

cosign sign-blob \
  --yes \
  --tlog-upload=false \
  --key labs/lab8/signing/cosign.key \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz

cosign verify-blob \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz
```

Saved evidence:
- `labs/lab8/artifacts/sample.txt`
- `labs/lab8/artifacts/sample.tar.gz`
- `labs/lab8/artifacts/sample.tar.gz.bundle`
- `labs/lab8/artifacts/verify-blob.txt`

Verification output:

```text
Verified OK
```

Use cases for non-container artifact signing:
- release binaries
- configuration files/manifests
- SBOM files distributed outside registry
- firmware and ML model artifacts

Difference from image signing:
- image signatures/attestations are stored and discovered via OCI registry
- blob signatures are distributed alongside file (bundle or detached signature)

---

## Acceptance Criteria Checklist

- [x] `labs/submission8.md` includes analysis and evidence for Tasks 1-3
- [x] Image pushed to local registry; Cosign signature created and verified
- [x] Tamper scenario demonstrated and explained
- [x] Attestations attached and verified (SBOM and provenance); payload inspected with `jq`
- [x] Artifact signing performed and verified
- [x] Outputs saved under `labs/lab8/`
