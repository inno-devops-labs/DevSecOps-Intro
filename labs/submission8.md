# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Local Registry, Signing & Verification

### Steps performed

1. Pulled `bkimminich/juice-shop:v19.0.0` and started a local registry (`registry:3`) on `localhost:5000`.
2. Tagged and pushed the image to the local registry.
3. Resolved the image digest reference:
   ```
   localhost:5000/juice-shop@sha256:b029fa83327aa8a3bbcaf161af6269c18c80134942437cb90794233502554e4
   ```
4. Generated a Cosign key pair (`cosign generate-key-pair`).
5. Signed the image using the private key and verified the signature with the public key.
6. Tamper demo: overwrote the `v19.0.0` tag with `busybox:latest`, re-resolved the digest, and confirmed:
   - Verification **failed** for the tampered image (`no signatures found`)
   - Verification **succeeded** for the original digest reference

### How signing protects against tag tampering

Tags are mutable pointers — anyone with push access can overwrite a tag to point to a different image (as demonstrated with the busybox swap). Cosign signatures are bound to the image's **content digest**, not the tag. So even if an attacker replaces the image behind a tag, the signature check will fail because the new content has a different digest that was never signed.

### What "subject digest" means

The subject digest is the SHA-256 hash of the image manifest content. It uniquely identifies the exact image layers and configuration. When Cosign signs an image, it signs this digest — meaning the signature is tied to the precise image content, not to any mutable metadata like tags. This is why verification still passed for the original digest after the tag was tampered with: the original content and its signature remained intact in the registry.

---

## Task 2 — Attestations: SBOM & Provenance

### Steps performed

1. Generated a Syft-native SBOM for the image and converted it to CycloneDX JSON format.
2. Attached the CycloneDX SBOM as an attestation to the image using `cosign attest --type cyclonedx`.
3. Verified the SBOM attestation with `cosign verify-attestation --type cyclonedx`.
4. Created a minimal SLSA Provenance v1 predicate JSON (with builder ID, image reference, and build timestamp).
5. Attached the provenance attestation using `cosign attest --type slsaprovenance`.
6. Verified the provenance attestation with `cosign verify-attestation --type slsaprovenance`.

### How attestations differ from signatures

A signature proves that a trusted party approved an image — it answers "who signed this?". An attestation goes further: it is a signed statement that attaches structured metadata (a **predicate**) to the image. It answers "what do we know about this image?". Attestations follow the in-toto format, wrapping the predicate in a DSSE envelope that binds it to the image digest. In short, a signature vouches for the image itself, while an attestation vouches for a specific claim *about* the image.

### What the SBOM attestation contains

The CycloneDX SBOM attestation contains a full software bill of materials for the image: a list of all packages, libraries, and dependencies present in the image along with their versions, licenses, and package URLs (purls). This allows consumers to audit the image for known vulnerabilities or license compliance issues without needing to scan the image themselves.

### What provenance attestations provide for supply chain security

Provenance attestations record *how* an image was built — who built it, when, with what parameters, and in what environment. This enables consumers to verify that the image was produced by a trusted build system and not tampered with after the build. In a CI/CD pipeline, automated provenance attestations provide an auditable chain from source code to deployed artifact, which is a core requirement of frameworks like SLSA.

---

## Task 3 — Artifact (Blob/Tarball) Signing

### Steps performed

1. Created a sample text file and packed it into a tarball (`sample.tar.gz`).
2. Signed the tarball using `cosign sign-blob` with the `--bundle` option, producing `sample.tar.gz.bundle`.
3. Verified the blob signature using `cosign verify-blob` with the bundle and public key.

### Use cases for signing non-container artifacts

- **Release binaries:** Signing compiled binaries (e.g., CLI tools, installers) lets users verify they downloaded the authentic file and it wasn't modified in transit or on the mirror.
- **Configuration files:** Signing Terraform plans, Kubernetes manifests, or Helm charts ensures that deployment configs haven't been tampered with before being applied.
- **Firmware and packages:** Signing firmware images or OS packages prevents supply chain attacks where a compromised distribution server serves malicious updates.

### How blob signing differs from container image signing

Container image signing operates through the OCI registry — the signature is stored as a separate OCI artifact linked to the image digest in the registry. Blob signing is registry-independent: it produces a **bundle file** (containing the signature and optional certificate/log metadata) that lives alongside the file on disk. Verification of a blob requires the bundle file and the public key, while image verification queries the registry for the associated signature artifact. Blob signing is more general-purpose and works for any file, whereas image signing is tightly integrated with the container ecosystem.
