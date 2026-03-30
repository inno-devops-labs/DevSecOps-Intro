# Lab 8 Submission — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Local Registry, Signing & Verification

### 1.1 Pull and Push to Local Registry

Pulled `bkimminich/juice-shop:v19.0.0` from Docker Hub, started a local registry on `localhost:5000`, then tagged and pushed the image:

```
docker pull bkimminich/juice-shop:v19.0.0
docker run -d --restart=always -p 5000:5000 --name registry registry:3
docker tag bkimminich/juice-shop:v19.0.0 localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

Digest reference resolved:
```
Using digest ref: localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48
```

### 1.2 Generate Cosign Key Pair

```
cosign generate-key-pair
# Output: cosign.key (private), cosign.pub (public)
```

Used an empty passphrase for the lab. In production, always use a strong passphrase.

### 1.3 Sign and Verify

Signed the image using the private key (with a custom signing-config that disables transparency log upload since this is a local registry lab):

```
cosign sign --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/signing-config.json \
  --key labs/lab8/signing/cosign.key \
  "localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48"
```

Verified the signature:

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

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48"},"image":{"docker-manifest-digest":"sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

Full output saved in `labs/lab8/analysis/verify-signature.txt`.

### 1.4 Tamper Demonstration

Replaced the image behind the `v19.0.0` tag with `busybox:latest` to simulate a supply chain attack (tag substitution):

```
docker tag busybox:latest localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
# New digest: sha256:11f85134f388cff5f4c66f9bb4c5942249c1f6f7eb8b3889948d953487b5f7a8
```

**Verify on tampered image → FAILS:**
```
Error: no signatures found
```

**Verify on original digest → PASSES:**
```
Verification for localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48 -- OK
```

Full tamper demo output saved in `labs/lab8/analysis/tamper-demo.txt`.

#### How signing protects against tag tampering

Docker image tags like `v19.0.0` are just pointers — anyone with registry write access can push a completely different image under the same tag. A tag gives you no guarantee about which actual image content you're running.

Cosign signs the **digest** (the cryptographic hash of the image content), not the tag. A digest like `sha256:b029fa...` uniquely identifies the exact image bytes. When you verify using a digest reference, Cosign checks that this specific content was signed by the trusted key. If someone swaps the image behind the tag, the digest changes, and verification fails with "no signatures found".

**Subject digest** is the `sha256:...` hash that cosign puts inside the signature as the "what was signed" field. It's the cryptographic fingerprint of the image manifest. When you run `cosign verify`, it checks that the digest of the image you're verifying matches the digest that was signed. This makes it impossible to reuse a valid signature for a different image.

---

## Task 2 — Attestations: SBOM & Provenance

### SBOM Generation

Reused the Syft-native SBOM from Lab 4 (`labs/lab4/syft/juice-shop-syft-native.json`) and converted it to CycloneDX JSON format:

```
docker run --rm \
  -v $(pwd)/labs/lab4/syft:/in:ro \
  -v $(pwd)/labs/lab8/attest:/out \
  anchore/syft:latest \
  convert /in/juice-shop-syft-native.json -o cyclonedx-json=/out/juice-shop.cdx.json
```

### 2.1 SBOM Attestation (CycloneDX)

Attached the SBOM as a CycloneDX attestation:

```
cosign attest --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/signing-config.json \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/juice-shop.cdx.json \
  --type cyclonedx \
  "$REF"
```

Verified the SBOM attestation:

```
cosign verify-attestation \
  --allow-insecure-registry \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --type cyclonedx \
  "$REF"
```

Output (verification header):
```
Verification for localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
```

Payload inspection with `jq` (`labs/lab8/attest/sbom-payload-inspect.json`):
```json
{
  "type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": {
    "name": "localhost:5000/juice-shop",
    "digest": {
      "sha256": "b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e48"
    }
  },
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:b3225b23-9710-4a17-97ea-417dc1c939ec",
  "componentCount": 3533
}
```

### 2.2 Provenance Attestation (SLSA)

Created a minimal SLSA provenance predicate and attached it:

```
cosign attest --yes \
  --allow-insecure-registry \
  --signing-config labs/lab8/signing/signing-config.json \
  --key labs/lab8/signing/cosign.key \
  --predicate labs/lab8/attest/provenance.json \
  --type slsaprovenance \
  "$REF"
```

Verified and decoded the provenance payload (`labs/lab8/attest/provenance-payload-inspect.json`):
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
    "builder": { "id": "student@local" },
    "buildType": "manual-local-demo",
    "invocation": {
      "configSource": {},
      "parameters": {
        "image": "localhost:5000/juice-shop@sha256:b029fa83..."
      }
    },
    "metadata": {
      "buildStartedOn": "2026-03-30T09:55:32Z",
      "completeness": { "parameters": true, "environment": false, "materials": false },
      "reproducible": false
    }
  }
}
```

Full verification output saved in `labs/lab8/attest/verify-provenance.txt`.

#### How attestations differ from signatures

A **signature** only proves that a specific image digest was approved by the key holder. It doesn't say anything about what is inside the image.

An **attestation** is a signed statement that contains actual metadata about the image — like its SBOM (list of software components and licenses), or provenance (where it came from, who built it, when). The metadata is wrapped in the in-toto envelope format and then signed with the same key. So an attestation = signature + meaningful content.

#### What the SBOM attestation contains

The SBOM attestation contains a CycloneDX bill of materials for the image. In this case it lists 3533 software components found inside `bkimminich/juice-shop:v19.0.0`, including npm packages with their names, versions, licenses, and package manager metadata. This lets you know exactly what software dependencies are bundled in the image and check for known vulnerabilities or license compliance issues.

#### What provenance attestations provide for supply chain security

Provenance attestations tell you the "origin story" of the image — who built it, with what tools, from what source, at what time. In production CI/CD this would include things like the git commit hash, the pipeline URL, and the build system identity. This lets you verify that the image actually came from your trusted build system and not from someone's laptop. Combined with SLSA levels, provenance attestations let you enforce policies like "only deploy images built by our official pipeline from a reviewed commit".

---

## Task 3 — Artifact (Blob/Tarball) Signing

Created a sample tarball and signed it using cosign sign-blob with a bundle file:

```
echo "sample content 2026-03-30" > labs/lab8/artifacts/sample.txt
tar -czf labs/lab8/artifacts/sample.tar.gz -C labs/lab8/artifacts sample.txt

cosign sign-blob \
  --yes \
  --signing-config labs/lab8/signing/signing-config.json \
  --key labs/lab8/signing/cosign.key \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz
```

Output:
```
Signing artifact...
Wrote bundle to file labs/lab8/artifacts/sample.tar.gz.bundle
```

Verified the blob signature:

```
cosign verify-blob \
  --insecure-ignore-tlog \
  --key labs/lab8/signing/cosign.pub \
  --bundle labs/lab8/artifacts/sample.tar.gz.bundle \
  labs/lab8/artifacts/sample.tar.gz
```

Output (`labs/lab8/artifacts/verify-blob.txt`):
```
Verified OK
```

#### Use cases for signing non-container artifacts

- **Release binaries** — signing executables or compiled binaries ensures users can verify the binary came from the official publisher and hasn't been modified.
- **Configuration files** — signing infrastructure configs (Terraform, Helm charts, Kubernetes manifests) ensures they haven't been tampered with between creation and deployment.
- **ML models** — signing model files ensures the model used in production is exactly what was validated during testing.
- **Packages and archives** — signing tarballs of software releases (like GitHub release assets) lets downstream users verify authenticity before installing.

#### How blob signing differs from container image signing

Container image signing works through an OCI registry — the signature is stored as a separate OCI artifact alongside the image in the registry, identified by the image digest. The registry acts as the distribution point for both the image and its signature.

Blob signing doesn't use a registry. The signature is stored in a local bundle file (a JSON file containing the signature and optional certificate). The bundle travels alongside the artifact — you distribute both the file and its bundle together. There's no central place to look up the signature; you need the bundle file explicitly. This makes it simpler for non-container use cases where you're just distributing files, but it means you have to manage the bundle file as part of your distribution process.

---

## Summary

| Task | Status | Evidence |
|------|--------|----------|
| Task 1 — Local registry, signing, verification | Done | `labs/lab8/analysis/verify-signature.txt` |
| Task 1 — Tamper demonstration | Done | `labs/lab8/analysis/tamper-demo.txt` |
| Task 2 — SBOM attestation (CycloneDX) | Done | `labs/lab8/attest/verify-sbom-attestation.txt`, `sbom-payload-inspect.json` |
| Task 2 — Provenance attestation (SLSA) | Done | `labs/lab8/attest/verify-provenance.txt`, `provenance-payload-inspect.json` |
| Task 3 — Blob/tarball signing | Done | `labs/lab8/artifacts/verify-blob.txt` |
