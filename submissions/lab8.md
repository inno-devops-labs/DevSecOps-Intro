# Lab 8 - Supply Chain: Signing, Tampering, and Attestation

## Task 1

### Selecting the digest

Signed image:

```text
127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

Original Docker Hub digest:

```text
sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0
```

Initially, RepoDigests was filtered by the localhost:5000/ prefix.
However, Docker inspect returned the original digest, while docker push
reported that only the available single-platform image had been published.
Therefore, the actual local manifest digest was retrieved through a HEAD
request to /v2/juice-shop/manifests/v20.0.0 using Docker-Content-Digest:

```text
HTTP/1.1 200 OK
Content-Type: application/vnd.oci.image.manifest.v1+json
Docker-Content-Digest: sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113
```

After an access error through localhost, 127.0.0.1 was used instead,
and NO_PROXY was configured for local addresses.

### Verifying the original signature

```bash
cosign verify --key labs/lab8/keys/cosign.pub \
  --insecure-ignore-tlog --allow-insecure-registry "$DIGEST"
```

Exit code: 0. The following verified claims were returned:

```json
[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"image":{"docker-manifest-digest":"sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":null}]
```

###

The juice-shop:v20.0.0 tag was overwritten with alpine:3.20.
The new digest retrieved from the registry was:

```text
127.0.0.1:5000/juice-shop@sha256:45e09956dc667c5eff3583c9d94830261fb1ca0be10a0a7db36266edf5de9e1d
```

Verification of the new digest failed with exit code 10:

```text
Error: no signatures found
error during command execution: no signatures found
```

Verification of the original digest after the swap succeeded with exit code 0
and returned claims containing docker-manifest-digest
sha256:cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113.
The result was saved in verify-original-after-tamper.json,
and the exit code in verify-original-after-tamper-exit.txt.

The signature binds the signed claims to a specific image manifest digest.
A tag is a mutable pointer: after the swap, v20.0.0 points to Alpine
with a different digest for which no signature exists.
The original digest continues to verify while its manifest and signature
remain available in the registry.
If signatures authenticated only the tag name without binding it to content,
reassigning the tag could make a different image appear to be signed.

## Task 2

### SBOM

The Lab 4 SBOM was attached to the original digest using cosign attest
with --type cyclonedx. The cosign verify-attestation command succeeded
with exit code 0; the payload was decoded, and its predicate was extracted
and compared with the original JSON.

```json
{
  "original_components": 3068,
  "verified_components": 3068,
  "identical": true
}
```

Both SBOMs use CycloneDX 1.7.
The predicateType extracted from the verified payload was:

```text
https://cyclonedx.org/bom
```

A second attestation was created with --type slsaprovenance.
Verification succeeded with exit code 0.
The decoded, verified statement was:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "127.0.0.1:5000/juice-shop",
      "digest": {
        "sha256": "cbdfc00de875926f20ff603fac73c5b68577e37680cf2e0c324adda42ffc1113"
      }
    }
  ],
  "predicate": {
    "builder": {
      "id": "https://localhost/lab8-student"
    },
    "buildType": "https://example.com/lab8/local-build",
    "invocation": {
      "configSource": {
        "uri": "https://github.com/ViAlexiV/DevSecOps-Intro"
      }
    }
  }
}
```

In both statements, Cosign populated _type with
https://in-toto.io/Statement/v0.1.
The subject contains the repository name and the original image's SHA256:
Cosign generated these fields from the image reference I supplied by digest.
Cosign generated predicateType from the selected --type:
cyclonedx or slsaprovenance.
I supplied the predicate content: the SBOM for the first attestation,
and builder, buildType, and invocation for the second.

The provenance is an educational example of a signed assertion.
I did not build the Juice Shop image, so these fields do not prove
its actual build process or achievement of a SLSA level.

### Responding to the next Log4Shell

A signed SBOM attestation enables searching for a vulnerable component
and its version across two thousand images, linking the dependencies
found to each image's digest.
An image signature alone authenticates the image's integrity and signer,
but does not provide a component inventory for that search.
To make this useful during an overnight incident, SBOMs must already be
available and searchable, and describe the corresponding images
with sufficient completeness and accuracy.
Their signatures must also be verified using a trusted key, and their
subject digests must match the images actually in use: a signature
alone does not prove that an SBOM is complete or correct.


## Bonus

### Signing and modifying the archive

An archive containing install.sh was signed using cosign sign-blob,
and the signature was saved in my-tool.tar.gz.bundle.
Verification of the original archive succeeded with exit code 0:

```text
Verified OK
```

Then install.sh was changed from echo "installing my-tool"
to echo "tampered installer", and the archive was rebuilt without re-signing.

Original archive SHA256:

```text
624818b2a4fa5bd4d3ac18f6de17b33706c3d9e6ce499b14912e18b2cc1a3295
```

Modified archive SHA256:

```text
ea4a41986a844ca83692134c74966a185f6f7a18c1e247e83c37f9e912b9ab78
```

Verification of the modified archive using the original bundle
failed with exit code 1:

```text
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

In addition to the archive itself, a consumer needs the public key cosign.pub
and the signature bundle my-tool.tar.gz.bundle.
The bundle may be distributed through the same channel as the archive.
The public key must be obtained from an independently trusted source
or checked against a previously trusted fingerprint: otherwise, replacing
both the archive and the key with an attacker's key would allow verification
to succeed.

Installation instructions must first require downloading the archive
and bundle to files, using a public key that is already trusted.
Next, the user must run cosign verify-blob and allow extraction
and execution of install.sh only if verification returns exit code 0.
If the signed archive is modified without the publisher's private key,
verification fails and installation must stop.
Projects often skip establishing trust in the public key and enforcing
verification before execution; a valid signature also does not guarantee
that the publisher released a safe script.

The scripts were not executed in this lab.