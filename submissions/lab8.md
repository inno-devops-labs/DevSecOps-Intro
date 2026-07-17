# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Local image pushed: `localhost:5000/juice-shop:v20.0.0` (to the local registry)
- Remote image used for signing: `index.docker.io/iamdlite/juice-shop` (pushed to Docker Hub for the signing demo)
- Image digest (canonical): `iamdlite/juice-shop@sha256:393d220c00ba8c57be2725043528908b45051c7b62da9d29a281c1eef3f6026a` (from `labs/lab8/results/juice-shop-digest.txt`)
- Short digest: `sha256:393d220c00ba8c57be2725043528908b45051c7b62da9d29a281c1eef3f6026a` 


### Signing
- Output of `cosign sign` (just the success line is fine):
```
Signing artifact... | Pushing signature to: index.docker.io/iamdlite/juice-shop
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[{"critical":{"identity":{"docker-reference":"index.docker.io/iamdlite/juice-shop@sha256:393d220c00ba8c57be2725043528908b45051c7b62da9d29a281c1eef3f6026a"},"image":{"docker-manifest-digest":"sha256:393d220c00ba8c57be2725043528908b45051c7b62da9d29a281c1eef3f6026a"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demo (FAILED — correctly)
Output of `cosign verify` on tampered digest:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies
```
Verification for index.docker.io/iamdlite/juice-shop@sha256:393d220c00ba8c57be2725043528908b45051c7b62da9d29a281c1eef3f6026a --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"index.docker.io/iamdlite/juice-shop@sha256:393d220c00ba8c57be2725043528-[REDACTED]"},"image":{"docker-manifest-digest":"sha256:393d22-[REDACTED]"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Why digest binding matters (Lecture 8 slide 6)
If Cosign had signed the mutable tag (:latest) instead of the immutable digest, an attacker could retag a malicious image with the same vulnerable tag and the signature would still verify successfully, since the signature is only bound to the tag name, not the actual image content. Because Cosign stores signatures as OCI artifacts keyed by the digest (sha256-<digest>.sig), signing the tag would break the entire security model—the verification would pass for the tampered image even though its content is completely different from what was originally signed, effectively rendering the signature useless for integrity verification.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (first 30 lines of decoded payload):
```json
{
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
      ],
      "name": "1to2",
      "purl": "pkg:npm/1to2@1.0.0",
      "type": "library",
      "version": "1.0.0"
    },
    {
      "author": "raffy.eth <raffy@me.com> (http://raffy.antistupid.com)",
      "bom-ref": "pkg:npm/%40adraffy/ens-normalize@1.10.1?package-id=08449108469244be",
      "cpe": "cpe:2.3:a:\\@adraffy\\/ens-normalize:\\@adraffy\\/ens-normalize:1.10.1:*:*:*:*:*:*:*",
      "description": "Ethereum Name Service (ENS) Name Normalizer",
      "externalReferences": [
        {
          "type": "distribution",
          "url": "git+https://github.com/adraffy/ens-normalize.js.git"
        },
        {
          "type": "website",
          "url": "https://github.com/adraffy/ens-normalize.js#readme"
        }
      ],
```
- Component count matches Lab 4 source: yes (3069 vs 3069)
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: `empty diff`

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
Lecture 8 slide 12 + Lecture 9 slide 4 — at K8s admission time, a Kyverno verify-images policy
can require BOTH signatures AND specific attestation predicates. What's the operational difference
between a "signed but no SBOM" image and a "signed with SBOM" image when the next Log4Shell hits?

A signed image without an SBOM provides integrity (it proves the image came from the claimed builder) but lacks component-level visibility, so operators cannot quickly determine which transitive dependencies are present. A signed image with a verified SBOM attestation enables automated vulnerability matching and admission controls to match known CVEs to exact components, allowing faster, precise blocking and remediation when a new vulnerability like Log4Shell is disclosed.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)
If Codecov consumers had used cosign verify-blob codecov.sh --key codecov.pub --certificate-identity codecov.io before executing the script, the attack would have failed because the tampered uploader would not have been signed by Codecov's private key. The verify-blob command checks the script's cryptographic signature against a public key, ensuring the file's integrity and authenticity before it ever reaches bash execution (Lecture 8 slide 14). Without this verification, consumers blindly executed a malicious script that stole their CI environment variables.