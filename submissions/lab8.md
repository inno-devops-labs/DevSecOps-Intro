# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `127.0.0.1:5050` *(port 5000 unavailable in WSL2 Docker; used 5050)*
- Image pushed: `127.0.0.1:5050/juice-shop:v20.0.0`
- Image digest: `127.0.0.1:5050/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe`

### Signing
```
Pushing signature to: 127.0.0.1:5050/juice-shop
```

### Verification (PASSED)
```json
[{"critical":{"identity":{"docker-reference":"127.0.0.1:5050/juice-shop"},"image":{"docker-manifest-digest":"sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe"},"type":"cosign container image signature"},"optional":null}]
```

### Tamper Demo (FAILED — correctly)
```
Error: no signatures found
error during command execution: no signatures found
```
(Tampered image: `127.0.0.1:5050/juice-shop@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e` — alpine:3.20 re-tagged as juice-shop.)

### Sanity — original still verifies
```
Verification for 127.0.0.1:5050/juice-shop@sha256:28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

### Why digest binding matters (Lecture 8 slide 6)
Cosign signs the **immutable digest** (`sha256:28870b9…`), not the mutable tag `v20.0.0`. When we pushed alpine under a juice-shop-looking tag, the digest changed to `sha256:c64c687c…` and verification failed — the signature stayed bound to the original bytes. If Cosign signed only the tag, an attacker could replace the image content behind the same tag (classic supply-chain swap) while verification still passed; digest binding prevents that.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation decoded statement (excerpt):
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://cyclonedx.org/bom",
  "subject": [{
    "name": "127.0.0.1:5050/juice-shop",
    "digest": { "sha256": "28870b9d2bec49e605d6ebbf4b22ed1ec1ca0a72347ef19217bbbb21ea44e3fe" }
  }],
  "predicate": { "components": [ "...3069 components..." ] }
}
```
- Component count matches Lab 4 source: **yes** (3069 = 3069)
- diff between Lab 4 SBOM and extracted attestation component count: *(empty — identical)*

### Provenance attestation
- Attached: yes
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

### What this gives a Lab 9 verifier (2-3 sentences)
At K8s admission (Lecture 8 slide 12 + Lab 9 Kyverno `verifyImages`), a policy can require **both** a valid Cosign signature **and** specific attestation types (CycloneDX SBOM, SLSA provenance). A **signed-but-no-SBOM** image proves publisher identity only — you still cannot instantly answer "which Log4j/log4shell-class dependency is inside?" A **signed + SBOM-attested** image lets the admission controller (or security bot) block deploy if the SBOM contains a known-vulnerable coordinate without waiting for a post-deploy Trivy scan.

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
Verified OK
```

### Tamper test failed (correctly)
```
Error: invalid signature when validating ASN.1 encoded signature
error during command execution: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)
Codecov's bash uploader was installed via `curl | bash` with no integrity check — attackers replaced the script in their CDN (Lecture 8 slide 14). If consumers ran `cosign verify-blob --bundle install.sh.bundle --key cosign.pub install.sh` **before** piping to bash, the modified byte stream would fail signature validation (as our tampered tarball did) and the malicious script would never execute. This is the same digest-bound trust model as image signing, applied to release artifacts.
