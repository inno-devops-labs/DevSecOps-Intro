# Lab 8 — Submission

I signed a Juice Shop image stored in a local registry, replaced the image behind its tag with Alpine, and checked which digest continued to pass signature verification. I also added and verified two different attestations, and performed the same tampering experiment against a signed release archive.

Both tampering attempts were detected as expected: the original image and original archive remained successfully verifiable.

**## Environment and reproducibility**

| Item                   | Version or reference                                                    |
| ---------------------- | ----------------------------------------------------------------------- |
| Run date               | 29 September 2026                                                       |
| Host                   | Windows, PowerShell; Python used for capturing output and decoding JSON |
| Docker client / server | 29.2.1 / 29.2.1                                                         |
| Cosign                 | v3.1.3, Windows/amd64                                                   |
| Registry               | `registry:3`, listening on `127.0.0.1:5000`                             |
| Application            | Juice Shop v20.0.0, Linux/amd64                                         |
| SBOM input             | CycloneDX generated with Syft 1.52.0; 3069 components                   |

Two environment-specific adjustments were required.

First, Cosign was installed on Windows with:

```powershell
winget install Sigstore.Cosign
```

The installation provided the executable as `cosign-windows-amd64`. I used this executable for the signing and verification commands described below.

Second, Docker initially pushed only the available Linux/amd64 manifest. Immediately after the push, the local `RepoDigests` information still referenced the source multi-platform index. Pulling the local tag refreshed the local metadata. I then selected the digest by filtering for the local registry prefix and independently checked it using `docker buildx imagetools inspect`.

For the successful image-signing and attestation commands, I explicitly disabled the signing configuration and used the legacy format. Blob signing also disables the signing configuration while keeping its bundle format. Later signing logs showed no Rekor upload.

These experiments use locally generated keys and a local registry. The transparency-log bypass options are therefore part of this isolated lab setup and should not be treated as the recommended approach for keyless CI signing.

**## Task 1**

**### Publish the image and identify the correct digest**

I first started the local registry and copied the pinned Juice Shop image into it:

```powershell
docker run -d --name lab8-registry -p 127.0.0.1:5000:5000 registry:3

docker tag bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0 localhost:5000/juice-shop:v20.0.0

docker push localhost:5000/juice-shop:v20.0.0

docker pull localhost:5000/juice-shop:v20.0.0

$DIGEST = docker inspect localhost:5000/juice-shop:v20.0.0 --format '{{range .RepoDigests}}{{println .}}{{end}}' |
  Where-Object { $_ -like 'localhost:5000/*' }

$DIGEST | Set-Content labs/lab8/results/juice-shop-digest.txt

docker buildx imagetools inspect localhost:5000/juice-shop:v20.0.0
```

The digest selected for signing was:

```text
localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```

I did not rely on the position of the digest in `RepoDigests`. Instead, I selected the entry beginning with `localhost:5000/`, which identifies the copy in the local registry.

Both the Docker push output and `docker buildx imagetools inspect` confirmed the digest:

`sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`.

The original upstream index was:

`sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`.

Inspection showed that the signed digest is its Linux/amd64 child manifest, which is also the platform represented by the SBOM used in this lab. Thus, the two digests represent an image index and its platform-specific child manifest rather than two separate application builds.

**### Create the signing key and validate the original image**

I generated the key pair with:

```powershell
cosign-windows-amd64 generate-key-pair --output-key-prefix labs/lab8/keys/cosign

git add labs/lab8/keys/cosign.key
```

The attempt to stage the private key failed with exit code **1**:

```text
The following paths are ignored by one of your .gitignore files:
labs/lab8/keys/cosign.key
hint: Use -f if you really want to add them.
hint: Disable this message with "git config advice.addIgnoredFile false"
```

The clean branch's `.gitignore` therefore prevented the private key from being staged. This result demonstrates the ignore rule rather than a pre-commit hook. I did not force-add the file with `git add -f`; only `cosign.pub` is included in the submission.

With `COSIGN_PASSWORD` provided for the signing operation, I used:

```powershell
cosign sign --key labs/lab8/keys/cosign.key --tlog-upload=false `
  --use-signing-config=false --new-bundle-format=false `
  --allow-insecure-registry --yes $DIGEST

cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog `
  --allow-insecure-registry $DIGEST
```

Both commands completed with exit code **0**.

The successful verification reported:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.

Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --

The following checks were performed on each of these signatures:

  - The cosign claims were validated

  - The signatures were verified against the specified public key
```

The corresponding JSON output was:

```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"cosign container image signature"},"optional":null}]
```

**### Overwrite the tag and test verification**

I then replaced the image behind the same registry tag with Alpine:

```powershell
docker pull alpine:3.20
docker tag alpine:3.20 localhost:5000/juice-shop:v20.0.0
docker push localhost:5000/juice-shop:v20.0.0
docker pull localhost:5000/juice-shop:v20.0.0

$TAMPERED = docker inspect localhost:5000/juice-shop:v20.0.0 --format '{{range .RepoDigests}}{{println .}}{{end}}' |
  Where-Object { $_ -like 'localhost:5000/*' }

cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog `
  --allow-insecure-registry $TAMPERED
```

The tag now resolved to a different digest:

```text
localhost:5000/juice-shop@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
```

Verification returned exit code **10**. The exact error was:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.

Error: no signatures found

error during command execution: no signatures found
```

Afterward, I verified the original `$DIGEST` again without restoring the `v20.0.0` tag. This verification returned exit code **0**, confirming the original signature was still valid:

```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"cosign container image signature"},"optional":null}]
```

The signature is associated with the image manifest digest and the supplied public key. The signed payload also contains the repository identity.

When the `v20.0.0` tag was moved to another digest, the new image did not inherit the signature of the previous image. The original digest continued to verify because neither its contents nor its signature had been changed.

If signatures were tied only to the tag name, moving the tag to a different image could leave the attacker with the same apparent approval even though the underlying content had changed.

**## Task 2**

**### Attach and verify the SBOM**

I attached the CycloneDX SBOM to `$DIGEST`, which still referred to the original Juice Shop manifest even though the tag itself had already been changed to Alpine:

```powershell
cosign attest --key labs/lab8/keys/cosign.key --type cyclonedx `
  --predicate labs/lab8/results/juice-shop.cdx.json `
  --tlog-upload=false --use-signing-config=false --new-bundle-format=false `
  --allow-insecure-registry --yes $DIGEST

cosign verify-attestation --key labs/lab8/keys/cosign.pub `
  --insecure-ignore-tlog --allow-insecure-registry --type cyclonedx $DIGEST
```

Both commands completed successfully with exit code **0**.

I decoded the `payload` from the verified JSON envelope, parsed it as the in-toto statement, and extracted its `predicate`:

```python
envelope = json.loads(verified_stdout)
statement = json.loads(base64.b64decode(envelope["payload"]))
extracted = statement["predicate"]

assert extracted == original_sbom
```

The results were:

| Check                                     | Result |
| ----------------------------------------- | -----: |
| Components in the original SBOM           |   3069 |
| Components in the verified/extracted SBOM |   3069 |
| Complete parsed JSON comparison           |   True |

The SHA-256 hash of the input SBOM was:

`5b48aeef336a4bfc26540443a07d01e7dacbc4a9d5ce65293f23bd1c459bf93b`.

I compared the complete parsed JSON objects rather than checking only the component count. This verifies that the entire predicate matches, including all component data and other fields, regardless of JSON formatting.

**### Add a second type of attestation**

For the second attestation, I supplied the following provenance predicate in `labs/lab8/results/provenance.json`:

```json
{
  "builder": { "id": "https://localhost/lab8-student" },
  "buildType": "https://example.com/lab8/local-build",
  "invocation": {
    "configSource": { "uri": "https://github.com/Mukhin-I/DevSecOps-Intro" }
  }
}
```

I attached and verified it with:

```powershell
cosign attest --key labs/lab8/keys/cosign.key --type slsaprovenance `
  --predicate labs/lab8/results/provenance.json `
  --tlog-upload=false --use-signing-config=false --new-bundle-format=false `
  --allow-insecure-registry --yes $DIGEST

cosign verify-attestation --key labs/lab8/keys/cosign.pub `
  --insecure-ignore-tlog --allow-insecure-registry --type slsaprovenance $DIGEST
```

Both operations returned exit code **0**.

After the second attestation was added, I repeated verification for both attestation types. Both continued to verify successfully.

The provenance information is an example of a self-authored claim created specifically for this exercise. I did not build the third-party Juice Shop image, so these signed fields do not demonstrate a SLSA level or independently prove how the image was built.

**### Inspect the verified attestation statements**

The following fields were extracted from the actual verified payloads. The `predicate` content itself is omitted here for readability.

CycloneDX statement:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      }
    }
  ]
}
```

SLSA provenance statement:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": {
        "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"
      }
    }
  ]
}
```

| Field                                      | Source                                                                                                                             |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `predicate`                                | Supplied by me as either the CycloneDX SBOM or the three-field provenance JSON.                                                    |
| `_type`                                    | Added by Cosign as part of the in-toto statement wrapper.                                                                          |
| `subject.name` and `subject.digest.sha256` | Generated by Cosign from the original digest-qualified image reference passed to the command.                                      |
| `predicateType`                            | Selected through `cyclonedx` or `slsaprovenance`; Cosign converted the selected type into the URI visible in the verified payload. |

In a Log4Shell-like incident, these attestations would allow an operator to search the SBOM inventories of all 2,000 images for the vulnerable package and version, and then determine the exact image digests that require investigation or replacement.

A signature alone proves that the artifact corresponds to the signed content, but does not provide a searchable inventory of the packages inside it.

For this to be useful during an incident, the attestations must still be retained and searchable, their signatures must be validated against trusted keys, and their subjects must correspond to the actual deployed image digests. The SBOMs also need to accurately represent the deployed contents: a valid signature does not by itself prove that the inventory is complete or that the software is free of vulnerabilities.

**## Bonus**

**### Sign the release archive and test a modification**

I created an `install.sh` containing:

```bash
#!/bin/bash
echo "installing my-tool"
```

and packaged it into `my-tool.tar.gz` using Python's `tarfile` module on Windows.

I then signed and verified the archive:

```powershell
cosign sign-blob --key labs/lab8/keys/cosign.key --yes `
  --tlog-upload=false --use-signing-config=false `
  --bundle labs/lab8/results/my-tool.tar.gz.bundle labs/lab8/results/my-tool.tar.gz

cosign verify-blob --key labs/lab8/keys/cosign.pub `
  --bundle labs/lab8/results/my-tool.tar.gz.bundle --insecure-ignore-tlog `
  labs/lab8/results/my-tool.tar.gz
```

Both commands returned exit code **0**.

The exact verification output included:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.

Verified OK
```

I then modified the second line of the script to:

```text
echo "modified installer for the tamper test"
```

and rebuilt the archive at the same path. I did not generate a new signature and did not execute either version of the script.

The resulting hashes were:

| Archive  | SHA-256                                                            |
| -------- | ------------------------------------------------------------------ |
| Original | `518a90b99918e02685e4d5d6ab03bf1625af5f4608823203d51c5751149a070a` |
| Modified | `0ab31e3888779adc4e70ec49eeb08859e222b5c90c3f30ea51c2b7dd22df4db6` |

Verification of the modified archive returned exit code **1**:

```text
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.

Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature

error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

**### Requirements for a consumer**

Besides the release archive itself, the consumer needs:

* `my-tool.tar.gz.bundle`
* a trusted `cosign.pub`

The bundle can be distributed through the same CDN as the archive because modifying the bundle cannot create a valid signature under the trusted public key.

The public key is different: it needs to be trusted through an independent authenticated channel or already pinned in the consumer's configuration. Downloading a replacement public key from the same compromised CDN would undermine the verification process.

For this offline, key-based example, I would publish installation instructions assuming Cosign is already installed and the trusted public key has already been provisioned at the specified path. The release domain below is only an example:

```bash
set -eu

work=$(mktemp -d)

trap 'rm -rf "$work"' EXIT

cd "$work"

release='https://downloads.example.com/my-tool/v1.0.0'

curl --fail --silent --show-error --location "$release/my-tool.tar.gz" -o my-tool.tar.gz

curl --fail --silent --show-error --location "$release/my-tool.tar.gz.bundle" -o my-tool.tar.gz.bundle

cosign verify-blob --key /etc/my-tool/trusted/cosign.pub \
  --bundle my-tool.tar.gz.bundle --insecure-ignore-tlog my-tool.tar.gz

tar -xzf my-tool.tar.gz

bash ./install.sh
```

The important property is that the archive is verified before it is extracted or executed. If an attacker modifies the archive or script without access to the trusted private key, verification fails and `set -e` prevents the installation from continuing.

The step that many projects omit is establishing and securely pinning the trusted public key, together with enforcing signature verification before executing the downloaded content.

This protects against the demonstrated content-substitution attack, although signature verification alone does not prevent an attacker from replaying an older release that was legitimately signed.

**## Final checks and cleanup**

* The original image successfully verified both before and after its tag was overwritten.
* The replacement Alpine image failed verification with `no signatures found`.
* Both attestation types were successfully attached and verified.
* The extracted SBOM matched the complete original JSON, including all 3069 components.
* The original release archive verified successfully, while the modified archive failed with an invalid-signature error.
* Only the report and public key are included in the submission; private signing material and local test evidence remain excluded.

Once all evidence had been collected, I removed the temporary registry with:

```powershell
docker rm -f lab8-registry
```

The registry, test images, and signatures were used only for this local exercise. The report preserves the relevant commands and outputs required to reproduce and review the results.
