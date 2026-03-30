# Lab 8 Submission — Software Supply Chain Security: Signing, Verification, and Attestations

**Target image:** `bkimminich/juice-shop:v19.0.0`
**Tool:** Cosign v3.0.5 (keyless-compatible, local key-pair signing)
**Registry:** `localhost:5000` (Distribution v3)

---

## Task 1 — Local Registry, Signing & Verification

### 1.1 Pull and push to local registry

```
docker pull bkimminich/juice-shop:v19.0.0          # already present locally
docker run -d -p 5000:5000 --name registry registry:3
docker tag bkimminich/juice-shop:v19.0.0 localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

Digest resolved from local registry:

```
Using digest ref: localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48
```

*(saved to `labs/lab8/analysis/ref.txt`)*

### 1.2 Cosign key pair generation

```
cosign generate-key-pair   # inside labs/lab8/signing/
# -> cosign.key (private), cosign.pub (public)
```

A signing config without a Rekor transparency log endpoint was also created to support offline/local signing (required in Cosign v3):

```
cosign signing-config create --no-default-rekor --no-default-fulcio --no-default-oidc \
  --out labs/lab8/signing/signing-config-notlog.json
```

### 1.3 Sign and verify

**Sign:**
```
cosign sign --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/signing-config-notlog.json \
  --key labs/lab8/signing/cosign.key \
  "localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48"
```
Output: `Signing artifact...` (success)

**Verify:**
```
cosign verify \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48"
```

Output:
```
Verification for localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48"},
  "image":{"docker-manifest-digest":"sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48"},
  "type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

*(full output saved to `labs/lab8/signing/verify-output.txt`)*

### 1.4 Tamper demonstration

A different image (`busybox:latest`) was pushed to the same tag `localhost:5000/juice-shop:v19.0.0`, replacing the original. Its digest is different from the one that was signed.

```
docker tag busybox:latest localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
# New digest: sha256:11f85134f388cff5f4c66f9bb4c5942249c1f6f7eb8b3889948d953487b5f7a8
```

**Verify tampered image (should FAIL):**
```
cosign verify --allow-insecure-registry --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "localhost:5000/juice-shop@sha256:11f85134f388cff5f4c66f9bb4c5942249c1f6f7eb8b3889948d953487b5f7a8"

Error: no signatures found
```

**Verify original signed digest (should PASS):**
```
cosign verify --allow-insecure-registry --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  "localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48"

Verification for localhost:5000/juice-shop@sha256:b029fa83... -- OK
```

*(full output saved to `labs/lab8/analysis/tamper-demo.txt`)*

**Analysis — how signing protects against tag tampering:**

A container image tag (e.g., `v19.0.0`) is a mutable pointer. An attacker or a misconfigured CI pipeline can silently overwrite it with a different image payload. Cosign's signature is bound not to the tag but to the **immutable content digest** (`sha256:...`). When Cosign verifies an image it checks that the cryptographic signature matches the exact digest of the manifest being inspected. If the tag now resolves to a different digest, there is no valid signature for that digest under the trusted public key — verification fails with `no signatures found`.

**What "subject digest" means:** The subject digest is the SHA-256 hash of the image manifest (the OCI manifest JSON, not the image layers). It uniquely identifies a specific image content. Because SHA-256 is collision-resistant, no two different images can share the same digest, making it a tamper-evident fingerprint.

---

## Task 2 — Attestations: SBOM & Provenance

### SBOM generation (Syft → CycloneDX)

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(pwd)":/tmp \
  anchore/syft:latest \
  "localhost:5000/juice-shop@sha256:b029fa83..." \
  -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json

docker run --rm \
  -v "$(pwd)/labs/lab4/syft":/in:ro \
  -v "$(pwd)/labs/lab8/attest":/out \
  anchore/syft:latest \
  convert /in/juice-shop-syft-native.json -o cyclonedx-json=/out/juice-shop.cdx.json
```

The generated CycloneDX 1.6 SBOM contains **3,533 components** (primarily npm packages from `juice-shop/node_modules`).

### 2.1 SBOM attestation (CycloneDX)

```
cosign attest --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/signing-config-notlog.json \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "localhost:5000/juice-shop@sha256:b029fa83..."
```

**Verify SBOM attestation:**
```
cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type cyclonedx \
  "localhost:5000/juice-shop@sha256:b029fa83..."
```

Output:
```
Verification for localhost:5000/juice-shop@sha256:b029fa83... --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
{"payload":"eyJfdHlwZSI6...","payloadType":"application/vnd.in-toto+json","signatures":[...]}
```

*(full output saved to `labs/lab8/attest/verify-sbom-attestation.txt`)*

### 2.2 Provenance attestation (SLSA)

```bash
cosign attest --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/signing-config-notlog.json \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/provenance.json \
  --type slsaprovenance \
  "localhost:5000/juice-shop@sha256:b029fa83..."
```

**Decoded provenance payload (via `jq`):**

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48"
      }
    }
  ],
  "predicate": {
    "builder": {"id": "student@local"},
    "buildType": "manual-local-demo",
    "invocation": {
      "configSource": {},
      "parameters": {
        "image": "localhost:5000/juice-shop@sha256:b029fa83..."
      }
    },
    "metadata": {
      "buildStartedOn": "2026-03-30T16:51:32Z",
      "completeness": {
        "parameters": true,
        "environment": false,
        "materials": false
      },
      "reproducible": false
    }
  }
}
```

*(saved to `labs/lab8/attest/provenance-decoded.json`)*

**Verify provenance attestation:**
```
cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type slsaprovenance \
  "localhost:5000/juice-shop@sha256:b029fa83..."
# -> Verified OK (output saved to labs/lab8/attest/verify-provenance.txt)
```

### Analysis

**How attestations differ from signatures:**
A Cosign *signature* answers the question "did the key holder approve this exact image digest?" — it is a cryptographic signature over the manifest digest, stored as an OCI artifact in the registry. An *attestation* is richer: it is a signed **in-toto Statement** envelope (`_type`, `predicateType`, `subject`, `predicate`) that binds a structured claim (e.g., an SBOM or build provenance) to the image digest. Attestations communicate *what* is in the image or *how* it was built, whereas a signature only communicates *who* approved it.

**What the SBOM attestation contains:**
The CycloneDX SBOM attestation lists all 3,533 software components discovered inside the `juice-shop:v19.0.0` image — primarily npm packages with their names, versions, licenses, CPEs, PURLs, and file paths inside the container. This enables consumers and security tools to know exactly which open-source dependencies are bundled, enabling vulnerability scanning and license compliance checks without re-analysing the image.

**What provenance attestations provide:**
A SLSA provenance attestation records *how* and *where* the image was built: the builder identity, build type, input parameters, and build timestamps. This allows downstream consumers to verify that the image was produced by a trusted CI system from a known source, closing a common supply chain attack vector where a binary is replaced between build and publish. Even in this minimal demo, the `builder.id`, `buildStartedOn`, and `subject.digest` create an auditable paper trail linking the signed digest to its build event.

---

## Task 3 — Artifact (Blob/Tarball) Signing

```bash
echo "sample content $(date -u)" > labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

cosign sign-blob \
  --yes \
  --signing-config labs/lab8/signing/signing-config-notlog.json \
  --key labs/lab8/signing/cosign.key \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz
# -> Wrote bundle to file labs/lab8/artifacts/sample.tar.gz.bundle

cosign verify-blob \
  --key labs/lab8/signing/cosign.pub \
  --insecure-ignore-tlog \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz
```

Output:
```
WARNING: Skipping tlog verification is an insecure practice...
Verified OK
```

*(saved to `labs/lab8/artifacts/verify-blob.txt`)*

### Analysis

**Use cases for signing non-container artifacts:**
- **Release binaries** (CLI tools, compiled binaries) — consumers can verify they downloaded the official, unmodified release.
- **Helm charts / Kubernetes manifests** — ensure deployment configurations were approved and not tampered with in transit.
- **Configuration files / Terraform plans** — prevent drift between reviewed and applied infrastructure state.
- **ML model weights or datasets** — sign model files to guarantee integrity before loading into production inference.

**How blob signing differs from container image signing:**
Container image signing targets an OCI manifest digest stored in a registry; the signature is stored as a co-located OCI artifact and discovered automatically via the registry API. Blob signing operates on arbitrary files (tarballs, binaries, configs) identified by their local SHA-256 digest; there is no registry to host the signature, so it is written into a portable **bundle file** (JSON containing the signature and optional certificate chain) that must be distributed alongside the artifact. Verification requires both the artifact and the bundle file to be present.

---

## Acceptance Criteria Checklist

- [x] Image pushed to local registry (`localhost:5000/juice-shop:v19.0.0`)
- [x] Cosign key pair generated; image signed by digest; signature verified
- [x] Tamper scenario demonstrated: busybox pushed under same tag → `no signatures found`; original digest still verifies OK
- [x] SBOM attestation (CycloneDX, 3,533 components) attached and verified; payload decoded with `jq`
- [x] Provenance attestation (SLSA) attached and verified; envelope decoded with `jq`
- [x] Blob signing: `sample.tar.gz` signed and verified via bundle
- [x] All outputs saved under `labs/lab8/`
