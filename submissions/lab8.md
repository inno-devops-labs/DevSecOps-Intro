# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `127.0.0.1:5001` (Distribution `registry:3`; port 5001 to avoid the macOS AirPlay Receiver on 5000)
- Image pushed: `127.0.0.1:5001/juice-shop:v20.0.0`
- Image digest: `127.0.0.1:5001/juice-shop@sha256:6d4baf6780d8f5dbf08d34cc417dd099c053ad6971112c5e61fa6145494c946b`

### Signing
Output of `cosign sign` (success line):
```
Pushing signature to: 127.0.0.1:5001/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on the original digest:
```json
Verification for 127.0.0.1:5001/juice-shop@sha256:6d4baf6780d8f5dbf08d34cc417dd099c053ad6971112c5e61fa6145494c946b --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"127.0.0.1:5001/juice-shop"},"image":{"docker-manifest-digest":"sha256:6d4baf6780d8f5dbf08d34cc417dd099c053ad6971112c5e61fa6145494c946b"},"type":"cosign container image signature"},"optional":null}]
```

### Tamper Demo (FAILED — correctly)
A different image (`alpine:3.20`) was re-tagged and pushed as `127.0.0.1:5001/juice-shop:v20.0.0-tampered`, resolving to a different digest (`sha256:45e09956…`). `cosign verify` on that digest:
```
Error: no signatures found
main.go:69: error during command execution: no signatures found
```

### Sanity — original still verifies
```
Verification for 127.0.0.1:5001/juice-shop@sha256:6d4baf6780d8f5dbf08d34cc417dd099c053ad6971112c5e61fa6145494c946b --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```

### Why digest binding matters
Cosign signed the image's immutable content digest (`sha256:…`), not the mutable `:v20.0.0` tag. The tamper attempt re-pointed the tag to a completely different image (alpine), which has a different digest, so verification against that digest finds no matching signature — while the original digest keeps verifying. Had Cosign signed the tag instead, the signature would "follow" whatever the tag points to: an attacker who re-pushes a malicious image under the same tag would inherit an apparently-valid signature, which is exactly the tag-mutation attack digest binding defeats.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx`, exit 0)
- `cosign verify-attestation --type cyclonedx` decoded predicate (first lines):
```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "components": [
    {
      "bom-ref": "pkg:npm/1to2@1.0.0?package-id=3cea2309a653e6ed",
      "cpe": "cpe:2.3:a:nodejs:1to2:1.0.0:*:*:*:*:*:*:*",
      "name": "1to2",
      "licenses": [ { "license": { "id": "MIT" } } ],
      ...
    }
  ]
}
```
- Component count matches Lab 4 source: yes
- diff between Lab 4 SBOM and extracted-from-attestation SBOM (empty = success):
```
DIFF EMPTY = MATCH
```

### Provenance attestation
- Attached: yes (`cosign attest --type slsaprovenance`, exit 0)
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`
- `cosign verify-attestation --type slsaprovenance`: exit 0, decoded predicate:
```json
{
  "builder": { "id": "https://localhost/lab8-student" },
  "buildType": "https://example.com/lab8/local-build",
  "invocation": {
    "configSource": {
      "uri": "https://github.com/student/repo",
      "digest": { "sha1": "abc123" }
    }
  }
}
```

### What this gives a Lab 9 verifier
At K8s admission time a Kyverno / Sigstore policy-controller `verify-images` rule can require BOTH a valid signature AND a specific attestation predicate before a pod is admitted. The operational difference is response speed: a "signed but no SBOM" image proves who built it but forces you to re-scan or rebuild to learn its contents, whereas a "signed with SBOM" image lets the next Log4Shell be answered by querying the already-attested component inventory (grep the CycloneDX predicate for the vulnerable coordinate) and lets admission control refuse anything lacking a fresh, signed SBOM — turning "re-scan the whole fleet" into "query the attestation".

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- `cosign verify-blob` success output:
```
Verified OK
```

### Tamper test failed (correctly)
```
Error: invalid signature when validating ASN.1 encoded signature
main.go:74: error during command execution: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation
Codecov's Bash Uploader was distributed via `curl | bash` with no signature check, so when an attacker modified the hosted script every CI consumer executed the tampered bytes. `cosign sign-blob` binds a signature to the exact byte stream of the artifact; if consumers had run `cosign verify-blob --key cosign.pub --bundle my-tool.tar.gz.bundle my-tool.tar.gz` before piping to `bash`, the modified script's hash would not match the signed bundle, `verify-blob` would exit non-zero, and the pipeline would abort before executing the malicious code.
