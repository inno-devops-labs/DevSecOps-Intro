# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`

Note: this digest is **not** the same one from Lab 7 (`sha256:fd58bdc9...`). Juice Shop is a
multi-platform image (amd64 + arm64), and I only have the amd64 blobs locally, so pushing to my
local registry only pushed the single-platform manifest — which gets its own digest. I first
tried `docker inspect --format '{{.RepoDigests}}'` and it still showed the old Docker Hub digest,
which turned out to be a caching quirk and just wrong. Had to ask the registry directly instead:
```
curl -s -D - -o /dev/null -H "Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json" \
  http://localhost:5000/v2/juice-shop/manifests/v20.0.0 | grep -i docker-content-digest
# Docker-Content-Digest: sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
```
Everything below is signed against this registry-confirmed digest, not the stale `docker inspect` one.

### Signing
```
Signing: localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe
Enter password for private key:
Signing artifact...
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```
Exit code: 0

### Tamper Demo (FAILED — correctly)
Re-tagged `alpine:3.20` as `localhost:5000/juice-shop:v20.0.0-tampered` and pushed it. The
registry confirmed a different digest (`sha256:c64c687c...`) from the signed original
(`sha256:28870b9d...`), as expected — different content, different digest.

Output of `cosign verify` on tampered digest:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```
Exit code: 10

### Sanity — original still verifies
```
Verification for localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```
Exit code: 0

### Why digest binding matters
Cosign signs the **digest**, not the tag. So the signature is really tied to `sha256:28870b9d...`,
not to whatever `v20.0.0` happens to point at right now. That's exactly why the tamper demo
failed correctly: the tampered tag pointed at a different digest with no signature attached, so
`verify` had nothing to match. If Cosign signed tags instead, an attacker could just re-push a
malicious image under the same tag (tags are mutable) and the old signature would still look
"valid" for whatever that tag currently resolves to. Digest binding is what actually makes the
signature mean something.

**Cosign version note:** I ended up with v3.1.1 installed (lab text assumes v2.x). Only bit that
broke because of it: `--tlog-upload=false` on the provenance attest step is deprecated in v3 and
throws an error. Just dropping the flag fixed it — keyed signing doesn't push to the public Rekor
log by default anyway, so it wasn't actually needed.

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` — exit 0, no output on success)
- Verify-attestation output (decoded payload, truncated to the envelope + first component):
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "localhost:5000/juice-shop",
      "digest": { "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe" }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX",
    "components": [ "... 3069 components ..." ]
  }
}
```
- Component count matches Lab 4 source: **yes** (3069 in both)
- `diff` between Lab 4 SBOM and the extracted-from-attestation SBOM: **empty** (exit 0) — the
  attested predicate is byte-identical in content to the original `labs/lab4/juice-shop.cdx.json`

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`
- `predicateType`: `https://slsa.dev/provenance/v0.2`, subject digest matches the signed image
  (`sha256:28870b9d...`) — confirmed via `cosign verify-attestation --type slsaprovenance`, exit 0

### What this gives a Lab 9 verifier
A "signed but no SBOM" image only tells you *who* built it. When the next Log4Shell hits, you'd
have to re-scan the image from scratch to know if it's affected. A "signed with SBOM" image means
a Kyverno policy (or anyone) can just pull the attestation, decode the CycloneDX predicate, and
`jq` through it to check for the vulnerable package — no re-scanning, no touching the actual image
layers. It turns "is this image affected?" from a fleet-wide re-scan into one quick query against
data you've already fetched and verified.

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` (a stand-in "release" tarball containing an installer script) +
  `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```
Exit code: 0

### Tamper test failed (correctly)
Appended a line (`MALICIOUS PAYLOAD`) to the downloaded tarball to simulate a compromised
distribution point re-serving a modified artifact under the same filename:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```
Exit code: 1

### Codecov 2021 mitigation
Codecov's bash uploader was just `curl | bash` with nothing verifying it — so when their CI infra
got compromised, attackers could swap in a modified script and every downstream pipeline would run
it without question. If Codecov had signed each release with `cosign sign-blob` and consumers ran
`cosign verify-blob --key codecov.pub --bundle uploader.sh.bundle uploader.sh` before executing it,
this would've failed exactly like my tamper test did — the modified bytes wouldn't match the
signature, `verify-blob` exits non-zero, and a CI step gating on that would just refuse to run
`bash uploader.sh`. Silent compromise turns into a loud, blocked build.
