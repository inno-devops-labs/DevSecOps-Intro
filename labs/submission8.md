# Lab 8 — Image Signing, Attestations, and Artifact Integrity

## 1. Image Signing and Verification

The Docker image `bkimminich/juice-shop:v19.0.0` was pushed to a local registry and referenced by digest:

```text
localhost:5000/juice-shop@sha256:772d62349859e4fe00737a68e3b3c80b1cb0cd1d2c9dc8ca3cbdcc50dcbff3a5
```

A Cosign key pair was generated and used to sign the image.

Verification was successful:
- the signature matched the image digest
- Cosign claims were validated
- the signature was verified with the public key

Evidence:
- `labs/lab8/analysis/verify.json`

## 2. Tampering Demonstration

The image tag `v19.0.0` was overwritten with a different image (`busybox:latest`).

The new digest became:

```text
sha256:c4e5b27bf840ba1ebd5568b6b914f6926f3559b2ad4f505b1f37aae483b907d6
```

Results:
- verification of the tampered image **failed** with `no signatures found`
- verification of the original signed digest still **passed**

This demonstrates that Cosign signatures protect the exact image digest, not just the tag name.
If an attacker replaces the tag with a different image, the old signature no longer validates for the new digest.

Evidence:
- `labs/lab8/analysis/ref-after-tamper.txt`
- terminal output from `cosign verify`

## 3. SBOM Attestation

An SBOM was generated with Syft in native Syft JSON format and then converted into CycloneDX JSON.

Created files:
- `labs/lab8/attest/juice-shop.cdx.json`
- `labs/lab8/attest/verify-sbom-attestation.txt`

The SBOM attestation was attached to the original image digest and then verified successfully with Cosign.

Why this matters:
- an SBOM provides a structured list of components inside the image
- attesting it allows consumers to verify that the SBOM is tied to the signed artifact
- this improves software supply chain transparency

## 4. Provenance Attestation

A provenance predicate was created manually in JSON format and attached to the image.

Created files:
- `labs/lab8/attest/provenance.json`
- `labs/lab8/attest/verify-provenance.txt`

The provenance attestation verification succeeded.

Why this matters:
- provenance records how or by whom an artifact was built
- it helps consumers evaluate trust in the software build process
- it supports supply chain security goals such as traceability and integrity

## 5. Blob / Artifact Signing

A non-container artifact was created:

- `sample.txt`
- archived into `sample.tar.gz`

Then the tarball was signed with Cosign using blob signing and a bundle was produced:

- `labs/lab8/artifacts/sample.tar.gz`
- `labs/lab8/artifacts/sample.tar.gz.bundle`

Blob verification succeeded with `Verified OK`.

### When blob signing is useful

Blob signing is useful for artifacts such as:
- release archives
- binaries
- SBOM files
- policy bundles
- configuration packages
- documents or exported reports

### Difference between blob signing and image signing

**Image signing**
- is used for OCI container images
- signs an image identified by digest in a registry
- is tied to registry-based distribution

**Blob signing**
- is used for standalone files
- signs the exact file content directly
- does not require the artifact to be stored as a container image

So image signing protects container artifacts in registries, while blob signing protects general files outside of OCI image workflows.

## 6. Security Value of the Lab

This lab demonstrated several important supply-chain security ideas:

1. **Digest-based trust**  
   Signatures apply to immutable digests, not mutable tags.

2. **Tamper detection**  
   Replacing a tag with different content breaks the trust relationship.

3. **Attestations add metadata trust**  
   SBOM and provenance attestations provide verifiable metadata connected to the artifact.

4. **Artifacts beyond containers also need integrity protection**  
   Blob signing extends integrity guarantees to tarballs and other files.

## 7. Conclusion

In this lab, I successfully:
- signed a container image with Cosign
- verified the image signature
- demonstrated tag tampering and verification failure on the tampered digest
- created and verified SBOM attestation
- created and verified provenance attestation
- signed and verified a non-container tarball artifact

Overall, the lab showed how image signing, attestations, and blob signing can be used together to improve software supply chain security and artifact integrity.
