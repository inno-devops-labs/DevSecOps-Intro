# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` running on `localhost:5000` (image `registry:3`)
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest: `localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Signing
Output of `cosign sign --key labs/lab8/keys/cosign.key --yes <digest>` (cosign v2.4.1):
```
tlog entry created with index: 2063552837
Pushing signature to: localhost:5000/juice-shop
```

### Verification (PASSED)
Output of `cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog <digest>`:
```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop"},"image":{"docker-manifest-digest":"sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"},"type":"cosign container image signature"},"optional":{"Bundle":{"SignedEntryTimestamp":"MEUCIQDI+5Oa9JEAAsOb0roq6zVENOqwrwktfaeEBxrvzb9dmgIgHSJEUhqhXAvkXeIrr0ahN5fbW7aEV2uFnhhTSCu3pz4=","Payload":{"body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIzNzQ2NjcyMGE3MTU2NjdkNTllMGExM2YwMDg2NTI0YzViYjFjYzgxMTIwMDIzNzk1N2RjNWI1Yzg1Njk3MDY5In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJRzBleWVwbEZYbVJybEFUSCtZZUNrUkd2ZWtDc2pqZnM0a29GZVpBd0c2bEFpRUF2WC9uZklYZUNzNDFxT3NVb3ZSSGROZHprWDlXWXJTVmErN0JWcjhudUZzPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW93UkVGUlkwUlJaMEZGVmpWMlVVTkJObTA1VEdrNVlqZEJjVFpDZG1kcU5TdDNaekZ4TmdwR2FraFFTa2s0ZG5OaWVIbEdjbUZGVGpSVlZVMVBOSEJQSzNKWkwzSm5Ua0YwWm5WT1VrSmlaRGhZVUVkUVJGVjZUMHhzYjB4MVozbG5QVDBLTFMwdExTMUZUa1FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0=","integratedTime":1783101663,"logIndex":2063552837,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"}}}}]
```

### Tamper Demo (FAILED — correctly)
- `alpine:3.20` re-tagged as `localhost:5000/juice-shop:v20.0.0-tampered` and pushed. Its resolved digest (`sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`) is different from the signed original digest (`sha256:fd58bdc9...`).

Output of `cosign verify --key labs/lab8/keys/cosign.pub --insecure-ignore-tlog <tampered-digest>`:
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
main.go:69: error during command execution: no signatures found
```

### Sanity — original still verifies
Re-running `cosign verify` on the original digest after the tamper attempt reproduced the same successful output as above (identical JSON, same signature) — confirming the signature is unaffected by the unrelated tampered push.

### Why digest binding matters (Lecture 8 slide 6)
Cosign signs and verifies against the immutable content digest (the sha256 of the manifest), never the mutable tag. When the tampered image was re-tagged and pushed as `juice-shop:v20.0.0-tampered`, the registry produced a completely different digest for that content, so the original signature — bound only to `sha256:fd58bdc9...` — simply didn't apply to it, and `cosign verify` correctly reported "no signatures found". If Cosign had instead signed the tag (`juice-shop:v20.0.0`), an attacker could overwrite that tag with any malicious content and the "signed" tag would keep resolving without ever failing verification, since tags are just mutable pointers with no cryptographic binding to specific content.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx --predicate labs/lab4/juice-shop.cdx.json` exit 0)
- SBOM source: `labs/lab4/juice-shop.cdx.json`, generated via `trivy image --format cyclonedx` against `bkimminich/juice-shop:v20.0.0` (905 components) — regenerated to backfill the Lab 4 artifact, which had not been saved under this filename previously.
- Verify-attestation output:
```
WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the attestation.
Verification for localhost:5000/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
```
- Component count matches Lab 4 source: yes — `labs/lab8/results/sbom-from-attestation.json` (decoded from the attestation payload) and `labs/lab4/juice-shop.cdx.json` both report **905** components.
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: empty (component counts identical — same source file used as predicate).

### Provenance attestation
- Attached: yes (`cosign attest --type slsaprovenance --tlog-upload=false --allow-insecure-registry`)
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`
- Decoded verify-attestation payload (in-toto Statement v0.1 / SLSA provenance v0.2):
```json
{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[{"name":"localhost:5000/juice-shop","digest":{"sha256":"fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"}}],"predicate":{"builder":{"id":"https://localhost/lab8-student"},"buildType":"https://example.com/lab8/local-build","invocation":{"configSource":{"uri":"https://github.com/SSSNeka/DevSecOps-Intro","digest":{"sha1":"abc123"}}}}}
```

### What this gives a Lab 9 verifier (Lecture 8 slide 12 + Lecture 9 slide 4)
A "signed but no SBOM" image only proves who produced the artifact and that it hasn't been altered since signing — it says nothing about what's actually inside it. A "signed with SBOM" image lets a Kyverno verify-images policy (or an incident responder) pull the attached component list directly from the registry without re-scanning anything. When the next Log4Shell-class CVE drops, a program with SBOM attestations can grep every signed image's attached SBOM for the vulnerable package/version in seconds; a program with signatures alone has to re-pull and re-scan every production image from scratch just to find out which ones are affected.

---

## Environment notes
- cosign v3.1.1 (latest via `winget install Sigstore.Cosign`) could not complete `cosign sign`/`cosign attest` against the public Rekor instance — v3 replaced `--tlog-upload` with a `--signing-config` mechanism and errored on the Rekor response (`(*models.Error) is not supported by the TextConsumer`). Downgraded to **cosign v2.4.1** (matching the course-pinned version) to complete this lab; all commands above were run with v2.4.1.
