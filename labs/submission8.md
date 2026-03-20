# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

**Name:** Baha Alimi  
**Branch:** `feature/lab8`  
**Target:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — Local Registry, Signing & Verification

### 1.1 Pull and Push to Local Registry

```powershell
docker pull bkimminich/juice-shop:v19.0.0
docker run -d --restart=always -p 5000:5000 --name registry registry:3
docker tag bkimminich/juice-shop:v19.0.0 localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

**Push output:**
```
The push refers to repository [localhost:5000/juice-shop]
v19.0.0: digest: sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58 size: 4276
Info → Not all multiplatform-content is present and only the available single-platform image was pushed
      sha256:2765a26de764... -> sha256:547bd3fef4a6...
```

> **Note:** The local registry digest (`sha256:547bd3...`) differs from the original Docker Hub digest (`sha256:2765a2...`) because only the `linux/amd64` single-platform manifest was pushed — the multi-platform index manifest is not preserved. All subsequent operations use the local registry digest.

**Digest resolved:**
```
Using digest ref: localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58
```

Saved to: `labs/lab8/analysis/ref.txt`

---

### 1.2 Cosign Key Pair Generation

```powershell
.\cosign.exe generate-key-pair --output-key-prefix labs/lab8/signing/cosign
```

**Output:**
```
Private key written to labs/lab8/signing/cosign.key
Public key written to labs/lab8/signing/cosign.pub
```

- `cosign.key` — ECDSA private key, passphrase-protected
- `cosign.pub` — corresponding public key used for verification

>The private key is passphrase-protected. In production, the private key should never be committed to version control and should be stored in a secrets manager (e.g. HashiCorp Vault, AWS KMS).

---

### 1.3 Sign and Verify the Image

**Sign:**
```powershell
.\cosign.exe sign --yes `
  --allow-insecure-registry `
  --key labs/lab8/signing/cosign.key `
  "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
```

The signature is stored as a separate OCI artifact in the local registry alongside the image, referenced by the image digest.

**Verify:**
```powershell
.\cosign.exe verify `
  --allow-insecure-registry `
  --insecure-ignore-tlog `
  --key labs/lab8/signing/cosign.pub `
  "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
```

**Verification output:**
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Verification for localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"},
"image":{"docker-manifest-digest":"sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"},
"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

✅ Signature verified. The JSON payload confirms:
- `docker-reference` — the exact registry path and digest that was signed
- `docker-manifest-digest` — the image content digest, cryptographically bound to the signature
- `type` — Cosign signing scheme v1

Saved to: `labs/lab8/signing/verify-original.txt`

---

### 1.4 Tamper Demonstration

**Simulate tampering** by pushing a completely different image (`busybox`) under the same tag:

```powershell
docker pull busybox:latest
docker tag busybox:latest localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

**New digest after tamper:**
```
After tamper digest ref: localhost:5000/juice-shop@sha256:70ce0a747f09cd7c09c2d6eaeab69d60adb0398f569296e8c0e844599388ebd6
```

**Verify the tampered image — FAILS:**
```powershell
.\cosign.exe verify `
  --allow-insecure-registry `
  --insecure-ignore-tlog `
  --key labs/lab8/signing/cosign.pub `
  "localhost:5000/juice-shop@sha256:70ce0a747f09cd7c09c2d6eaeab69d60adb0398f569296e8c0e844599388ebd6"
```

**Output:**
```
WARNING: Skipping tlog verification is an insecure practice...
Error: no signatures found
error during command execution: no signatures found
```

❌ Verification correctly fails — the replaced image has no valid signature.

**Sanity check — original digest still verifies:**
```
Verification for localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58 --
  - The cosign claims were validated
  - The signatures were verified against the specified public key
✅ Original digest still passes verification
```

Saved to: `labs/lab8/analysis/ref-after-tamper.txt`, `labs/lab8/signing/verify-tamper.txt`

---

### Analysis: How Signing Protects Against Tag Tampering

**The problem with tags:** Docker image tags (e.g. `v19.0.0`) are mutable pointers — anyone with push access to a registry can overwrite them with a completely different image. A CI/CD pipeline that pulls `myimage:v1.0` today may get a different image tomorrow with the same tag.

**How digest-based signing solves this:** Cosign signs the image *manifest digest* (a SHA-256 hash of the image content), not the tag. The signature is cryptographically bound to a specific content hash. When Cosign verifies `localhost:5000/juice-shop@sha256:547bd3...`, it checks that:
1. A valid signature exists for exactly that digest
2. The signature was produced by the holder of the trusted private key

If an attacker replaces the image under the same tag, the new content produces a different digest. The old signature does not apply to the new digest, so verification fails with `no signatures found`.

**What "subject digest" means:** The subject digest is the SHA-256 hash of the image manifest — the canonical identifier of a specific image version. It is immutable: the same content always produces the same digest, and any change to the image produces a completely different digest. Signing by subject digest rather than by tag ensures the signature is tied to specific, verifiable content rather than a mutable label.

---

## Task 2 — Attestations: SBOM and Provenance

### 2.1 CycloneDX SBOM Attestation

The Lab 4 Syft-native SBOM (`labs/lab4/syft/juice-shop-syft-native.json`) was converted to CycloneDX JSON format:

```powershell
docker run --rm `
  -v "${PWD}/labs/lab4/syft:/in" `
  -v "${PWD}/labs/lab8/attest:/out" `
  anchore/syft:latest `
  convert /in/juice-shop-syft-native.json -o cyclonedx-json=/out/juice-shop.cdx.json
```

Output: `labs/lab8/attest/juice-shop.cdx.json`

**Attach SBOM attestation:**
```powershell
.\cosign.exe attest --yes `
  --allow-insecure-registry `
  --key labs/lab8/signing/cosign.key `
  --predicate labs/lab8/attest/juice-shop.cdx.json `
  --type cyclonedx `
  "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
```

**Verify SBOM attestation:**
```powershell
.\cosign.exe verify-attestation `
  --allow-insecure-registry `
  --insecure-ignore-tlog `
  --key labs/lab8/signing/cosign.pub `
  --type cyclonedx `
  "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
```

**Output (truncated):**
```
WARNING: Skipping tlog verification is an insecure practice...
Verification for localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQv...","payloadType":"application/vnd.in-toto+json","signatures":[...]}
```

✅ SBOM attestation verified. The payload is a base64-encoded in-toto statement wrapping the full CycloneDX SBOM (1,001 packages).

Full output saved to: `labs/lab8/attest/verify-sbom-attestation.txt`

---

### 2.2 Provenance Attestation

**Provenance predicate (`labs/lab8/attest/provenance.json`):**
```json
{
  "_type": "https://slsa.dev/provenance/v1",
  "buildType": "manual-local-demo",
  "builder": {"id": "student@local"},
  "invocation": {"parameters": {"image": "localhost:5000/juice-shop@sha256:547bd3..."}},
  "metadata": {"buildStartedOn": "2026-03-20T03:36:14Z", "completeness": {"parameters": true}}
}
```

**Attach provenance attestation:**
```powershell
.\cosign.exe attest --yes `
  --allow-insecure-registry `
  --key labs/lab8/signing/cosign.key `
  --predicate labs/lab8/attest/provenance.json `
  --type slsaprovenance `
  "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
```

**Verify and inspect provenance:**
```powershell
.\cosign.exe verify-attestation `
  --allow-insecure-registry `
  --insecure-ignore-tlog `
  --key labs/lab8/signing/cosign.pub `
  --type slsaprovenance `
  "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
```

**Decoded payload (base64 → JSON):**
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
      }
    }
  ],
  "predicate": {
    "builder": {"id": "student@local"},
    "buildType": "manual-local-demo",
    "invocation": {
      "configSource": {},
      "parameters": {
        "image": "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
      }
    },
    "metadata": {
      "buildStartedOn": "2026-03-20T03:36:14Z",
      "completeness": {"parameters": true, "environment": false, "materials": false},
      "reproducible": false
    }
  }
}
```

✅ Provenance attestation verified and decoded. Full output saved to: `labs/lab8/attest/verify-provenance.txt`

---

### 2.3 Payload Inspection with `jq`

**Provenance attestation — full payload decoded:**

```powershell
.\cosign.exe verify-attestation `
  --allow-insecure-registry `
  --insecure-ignore-tlog `
  --key labs/lab8/signing/cosign.pub `
  --type slsaprovenance `
  "$REF" | jq '.payload | @base64d | fromjson'
```

**Output:**
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
      }
    }
  ],
  "predicate": {
    "builder": {
      "id": "student@local"
    },
    "buildType": "manual-local-demo",
    "invocation": {
      "configSource": {},
      "parameters": {
        "image": "localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
      }
    },
    "metadata": {
      "buildStartedOn": "2026-03-20T03:36:14Z",
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

**SBOM attestation — envelope metadata (subject and type only, full predicate omitted for brevity):**

```powershell
.\cosign.exe verify-attestation `
  --allow-insecure-registry `
  --insecure-ignore-tlog `
  --key labs/lab8/signing/cosign.pub `
  --type cyclonedx `
  "$REF" | jq '.payload | @base64d | fromjson | {_type, predicateType, subject}'
```

**Output:**
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58"
      }
    }
  ]
}
```

**Key observations from `jq` inspection:**

- Both attestations share the same in-toto Statement envelope (`_type: https://in-toto.io/Statement/v0.1`) and the same `subject` digest — proving both are bound to exactly the same image content
- The `predicateType` field distinguishes attestation types: `https://slsa.dev/provenance/v0.2` for provenance vs `https://cyclonedx.org/bom` for the SBOM
- The provenance `predicate` reveals the builder identity (`student@local`), build timestamp (`2026-03-20T03:36:14Z`), and completeness flags — in a real CI/CD pipeline this would show the GitHub Actions runner ID, workflow SHA, and source repository
- The `jq` pipeline `.payload | @base64d | fromjson` is the standard pattern for inspecting any Cosign attestation: extract the base64 payload field, decode it, then parse as JSON

---

### Analysis: Attestations vs Signatures

**Signatures** answer the question *"who vouches for this image?"* — they are a cryptographic proof that a specific key holder approved a specific image digest. They contain no information about the image's contents or how it was built.

**Attestations** answer *"what is this image, and where did it come from?"* — they are signed statements that attach structured metadata (a *predicate*) to an image. The predicate can contain anything: an SBOM, build provenance, test results, vulnerability scan results, or deployment policies. The attestation envelope (in-toto Statement) binds the metadata to the subject digest, and the whole envelope is signed with Cosign.

The key structural difference:
- A **signature** is just: `sign(digest)`
- An **attestation** is: `sign(in-toto_statement(subject=digest, predicate=metadata))`

**What the SBOM attestation contains:** The CycloneDX SBOM attestation embeds the complete software bill of materials — all 1,001 packages (990 npm, 10 Debian, 1 binary) with their versions, licenses, and CPE identifiers — cryptographically bound to the image digest. Any consumer who verifies the attestation gets a tamper-evident inventory of every dependency in the image.

**What provenance attestations provide for supply chain security:** Provenance records *how* an artifact was built — the builder identity, build parameters, timestamp, and source inputs. This enables consumers to verify that an image was built by a trusted CI system from expected source code, not by an attacker who compromised a developer machine. In SLSA framework terms, provenance attestations are the foundation for achieving higher supply chain integrity levels (SLSA L2/L3 require signed provenance from a hardened build platform).

---

## Task 3 — Artifact (Blob/Tarball) Signing

### Commands

```powershell
# Create artifact
echo "sample content 2026-03-19" | Out-File labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

# Sign blob
.\cosign.exe sign-blob `
  --yes `
  --key labs/lab8/signing/cosign.key `
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle `
  labs/lab8/artifacts/sample.tar.gz
```

**Output:**
```
Using payload from: labs/lab8/artifacts/sample.tar.gz
Wrote bundle to file labs/lab8/artifacts/sample.tar.gz.bundle
```

### Verification

```powershell
.\cosign.exe verify-blob `
  --key labs/lab8/signing/cosign.pub `
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle `
  labs/lab8/artifacts/sample.tar.gz
```

**Output:**
```
Verified OK
```

✅ Blob verification successful. Output saved to: `labs/lab8/artifacts/verify-blob.txt`

### How the Bundle Works

Unlike container image signing (where the signature is stored as a separate OCI artifact in the registry), blob signing has nowhere to store the signature remotely. The `--bundle` flag writes a self-contained JSON file alongside the artifact containing both the signature and the public key certificate. The bundle file must be distributed together with the artifact for verification to succeed.

---

### Analysis: Blob Signing vs Container Image Signing

| Aspect | Container Image Signing | Blob Signing |
|--------|------------------------|--------------|
| **Signature storage** | Stored in OCI registry as a separate manifest, referenced by digest | Stored in a local `.bundle` JSON file alongside the artifact |
| **Distribution** | Signature automatically available to anyone with registry access | Bundle file must be explicitly distributed with the artifact |
| **Reference mechanism** | Referenced by image manifest digest (immutable) | Referenced by file content hash in the bundle |
| **Verification dependency** | Requires registry access | Requires only the bundle file and public key |
| **Use case** | Container images in registries | Release binaries, SBOMs, configs, tarballs, scripts |

**Use cases for signing non-container artifacts:**

1. **Release binaries** — Sign compiled executables so users can verify they downloaded an authentic, unmodified binary directly from the publisher (equivalent to GPG-signed release assets on GitHub)
2. **SBOM files** — Sign the SBOM itself so consumers know the bill of materials was produced by a trusted tool and has not been tampered with after generation
3. **Configuration files** — Sign Kubernetes manifests, Terraform plans, or Ansible playbooks before applying them to production, ensuring no modification occurred in transit through CI/CD pipelines
4. **Compliance artifacts** — Sign audit reports, test results, and scan outputs to create a tamper-evident audit trail for regulatory requirements (SOC 2, PCI-DSS)
5. **IaC templates** — Sign Helm charts or CloudFormation templates distributed through artifact repositories to prevent supply chain substitution attacks

---

## Environment Notes

- **Host OS:** Windows 11
- **Docker:** 29.2.0
- **Cosign:** v3.0.5 (windows/amd64)
- **Registry:** `registry:3` on `localhost:5000`
- **Cosign v3 note:** `--tlog-upload=false` is deprecated in v3. Signing was performed without this flag; transparency log upload was suppressed by signing to a local insecure registry (no Rekor submission occurs for local-only registries). Verification used `--insecure-ignore-tlog` to skip Rekor lookup in this local lab context.

---

## Repository Structure

```
labs/lab8/
├── analysis/
│   ├── ref.txt                          # Original digest reference
│   └── ref-after-tamper.txt            # Post-tamper digest reference
├── signing/
│   ├── cosign.key                       # Private key (passphrase-protected) Not commited
│   ├── cosign.pub                       # Public key
│   ├── signing-config.json             # Signing config (no tlog)
│   ├── verify-original.txt             # Verification output — original image
│   └── verify-tamper.txt               # Tamper verification — failed as expected
├── attest/
│   ├── juice-shop.cdx.json             # CycloneDX SBOM (converted from Lab 4)
│   ├── provenance.json                 # SLSA provenance predicate
│   ├── verify-sbom-attestation.txt     # SBOM attestation verification output
│   └── verify-provenance.txt           # Provenance attestation verification output
└── artifacts/
    ├── sample.txt                       # Sample file content
    ├── sample.tar.gz                    # Signed tarball
    ├── sample.tar.gz.bundle            # Cosign signature bundle
    └── verify-blob.txt                 # Blob verification output
```