# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Local Registry, Signing & Verification

### Image reference (digest)

Image was pushed to a local registry and referenced using a digest:

```
localhost:5000/juice-shop@<original-digest>
```

Saved in:

```
labs/lab8/analysis/ref.txt
```

### Signing

The image was signed using Cosign with a locally generated key pair:

```
cosign sign --key cosign.key <digest-ref>
```

Output saved in:

```
labs/lab8/signing/sign-image.txt
```

### Verification

The signature was successfully verified using the public key:

```
cosign verify --key cosign.pub <digest-ref>
```

Output saved in:

```
labs/lab8/signing/verify-image.txt
```

Verification confirms that:

* The image digest matches the signed subject
* The signature was created with the corresponding private key

### Tamper Demonstration

The tag `v19.0.0` was intentionally overwritten with another image (`busybox`):

```
docker tag busybox:latest localhost:5000/juice-shop:v19.0.0
docker push localhost:5000/juice-shop:v19.0.0
```

A new digest was retrieved:

```
localhost:5000/juice-shop@<tampered-digest>
```

Saved in:

```
labs/lab8/analysis/ref-after-tamper.txt
```

### Verification after tampering

Verification of the **tampered digest failed**:

```
cosign verify <tampered-digest>
```

Saved in:

```
labs/lab8/signing/verify-tampered.txt
```

Verification of the **original digest still succeeded**:

```
cosign verify <original-digest>
```

Saved in:

```
labs/lab8/signing/verify-original-after-tamper.txt
```

### Explanation

- **Tags are mutable**: they can be reassigned to different images
- **Digests are immutable**: they uniquely identify image content
- Cosign signs the **subject digest**, not the tag

This means:

- Even if an attacker replaces an image under the same tag, verification fails
- Only the originally signed digest remains trusted

## Task 2 — Attestations (SBOM & Provenance)

### SBOM Attestation

A CycloneDX SBOM was generated using Syft and attached as an attestation:

```
cosign attest --type cyclonedx --predicate juice-shop.cdx.json
```

Verification:

```
cosign verify-attestation --type cyclonedx
```

Saved in:

```
labs/lab8/attest/verify-sbom-attestation.txt
```

### SBOM contents

The SBOM contains:

* List of packages and dependencies
* Versions of installed components
* Dependency relationships
* Metadata about the container image

This helps identify:

* Vulnerabilities
* Outdated dependencies
* Supply chain risks

### Provenance Attestation

A minimal SLSA provenance predicate was created and attached:

```
cosign attest --type slsaprovenance --predicate provenance.json
```

Verification:

```
cosign verify-attestation --type slsaprovenance
```

Saved in:

```
labs/lab8/attest/verify-provenance.txt
```

### Provenance contents

The provenance attestation includes:

- Builder identity (`student@local`)
- Build type (`manual-local-demo`)
- Input parameters (image reference)
- Build timestamp

This provides:

- Traceability of how the artifact was created
- Information about who built it
- Context for verifying build integrity

### Attestations vs Signatures

| Feature  | Signature | Attestation |
| --- | --- | --- |
| Purpose | Verify integrity & authenticity | Provide metadata about artifact |
| Bound to | Image digest| Image digest |
| Content | Cryptographic signature | JSON predicate (SBOM, provenance) |
| Use case | Trust verification | Supply chain transparency |

## Task 3 — Artifact (Blob) Signing

### Artifact creation

A sample tarball was created:

```
sample.tar.gz
```

### Signing

The artifact was signed using Cosign:

```
cosign sign-blob --bundle sample.tar.gz.bundle sample.tar.gz
```

Saved in:

```
labs/lab8/artifacts/sign-blob.txt
```

### Verification

The signature was verified using the public key and bundle:

```
cosign verify-blob --bundle sample.tar.gz.bundle
```

Saved in:

```
labs/lab8/artifacts/verify-blob.txt
```

### Use cases for blob signing

* Release binaries
* Configuration files
* Infrastructure artifacts (Terraform plans, manifests)
* CI/CD outputs

### Blob vs Image signing

| Feature | Image Signing | Blob Signing |
| --- | --- | --- |
| Target | Container image | Any file (tar, binary, etc.) |
| Storage | Registry | Local or distributed |
| Metadata | OCI manifest | External bundle |
| Use case | Container security | General artifact integrity |

## Conclusion

In this lab, the following concepts were demonstrated:

* Image signing ensures integrity and authenticity
* Digest-based verification prevents tag tampering attacks
* Attestations provide transparency into software supply chains
* SBOM helps identify dependencies and vulnerabilities
* Provenance adds traceability to builds
* Blob signing extends trust beyond containers

Together, these techniques improve supply chain security by ensuring that only trusted and verified artifacts are used in deployment.
