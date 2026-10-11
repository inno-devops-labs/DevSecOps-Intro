# Lab 8 — Submission

## Task 1: Sign + Tamper Demo

### Registry + image push
- Registry container: `lab8-registry` (Distribution v3, `registry:3`) running on `127.0.0.1:5000`
- Image pushed: `127.0.0.1:5000/juice-shop:v20.0.0`
- Image digest:
```
127.0.0.1:5000/juice-shop@sha256:760042c54214cbb86f6009bd56218b6bac11044605b51d0c4478a5a384106365
```

> **Environment note:** the lab instructions use `localhost:5000`. On this machine `localhost` resolves to `::1` first, and macOS's built-in AirPlay Receiver service already listens on port 5000 on the IPv6 loopback (`Server: AirTunes` in the response headers) — it returned `403 Forbidden` before any request reached the registry. `docker push` still worked because the Docker daemon resolves `localhost` inside its own Linux VM, but `cosign` (running natively on the Mac) hit AirPlay instead. Fix: use `127.0.0.1:5000` explicitly everywhere instead of `localhost:5000` (same registry, same digest — verified `docker push` re-uses all cached layers). All commands below were run with `--allow-http-registry` since the local registry has no TLS.

### Signing
Output of `cosign sign`:
```
Signing artifact...
Pushing signature to: 127.0.0.1:5000/juice-shop
```

### Verification (PASSED)
Output of `cosign verify` on original digest:
```json
[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:760042c54214cbb86f6009bd56218b6bac11044605b51d0c4478a5a384106365"},"image":{"docker-manifest-digest":"sha256:760042c54214cbb86f6009bd56218b6bac11044605b51d0c4478a5a384106365"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

### Tamper Demo (FAILED — correctly)
`alpine:3.20` was re-tagged as `127.0.0.1:5000/juice-shop:v20.0.0-tampered` and pushed, producing a different digest (`sha256:d10bea75...`, vs. the original `sha256:760042c5...`). Output of `cosign verify` on the tampered digest:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the signature.
Error: no signatures found
error during command execution: no signatures found
```

### Sanity — original still verifies
```
Verification for 127.0.0.1:5000/juice-shop@sha256:760042c54214cbb86f6009bd56218b6bac11044605b51d0c4478a5a384106365 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"127.0.0.1:5000/juice-shop@sha256:760042c54214cbb86f6009bd56218b6bac11044605b51d0c4478a5a384106365"},"image":{"docker-manifest-digest":"sha256:760042c54214cbb86f6009bd56218b6bac11044605b51d0c4478a5a384106365"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```
Exit code: 0 — unaffected by the tamper attempt above, because verification is keyed off the digest, not the container name.

### Why digest binding matters (Lecture 8 slide 6)
Cosign signs the image **digest** (`sha256:760042c5...`), not the tag (`v20.0.0`). A tag is just a mutable pointer a registry lets anyone overwrite; the digest is a cryptographic hash of the actual manifest content, so it changes the instant the underlying bytes change. That's why re-tagging `alpine` as `juice-shop:v20.0.0-tampered` produced a completely different digest, and `cosign verify` against that new digest found "no signatures found" — the attacker's image was never signed. If Cosign had signed the tag instead, an attacker (or a compromised registry) could silently repoint `v20.0.0` at a malicious image and the signature would appear to "cover" it, since verification would resolve the tag to whatever content currently sits behind it rather than to the specific bytes that were actually reviewed and signed.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation
- Attached: yes (`cosign attest --type cyclonedx` exit 0)
- Verify-attestation output (decoded envelope metadata):
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "127.0.0.1:5000/juice-shop",
      "digest": {
        "sha256": "760042c54214cbb86f6009bd56218b6bac11044605b51d0c4478a5a384106365"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom"
}
```
The decoded `.predicate` itself is the full CycloneDX document (`bomFormat`, `specVersion`, `serialNumber`, `metadata`, `components`, `dependencies` — same top-level shape as the Lab 4 source file).
- Component count matches Lab 4 source: **yes** — both report `3068` components (`jq '.components | length'`)
- diff between Lab 4 SBOM and the extracted-from-attestation SBOM: empty (exit 0) — component counts are byte-for-byte identical

### Provenance attestation
- Attached: yes (`cosign attest --type slsaprovenance` exit 0)
- Builder ID in predicate: `https://localhost/lab8-student`
- buildType in predicate: `https://example.com/lab8/local-build`

> **cosign v3.1.1 note:** the lab's `--tlog-upload=false` flag is deprecated/removed in Cosign v3.x (`--tlog-upload has been deprecated ... not supported with --signing-config`). Since this is keyed signing (not Fulcio/keyless), no transparency-log upload was attempted in the first place, so the attest command was re-run without that flag: `cosign attest --key cosign.key --type slsaprovenance --predicate predicate-only.json --allow-insecure-registry --allow-http-registry --yes <digest>`.

### What this gives a Lab 9 verifier (2-3 sentences)
A "signed but no SBOM" image only proves *who* built the image and that it hasn't been tampered with since — it says nothing about *what's inside*. A "signed with SBOM" image lets a Kyverno `verify-images` policy (or any downstream consumer) pull the attached CycloneDX attestation and immediately answer "does this running workload contain `log4j-core 2.14.1`?" without re-scanning the filesystem or waiting on a fresh Trivy/Grype run. When the next Log4Shell drops, that's the difference between grepping a database of already-signed, already-inventoried SBOMs across the fleet in minutes versus scrambling to re-scan every running image from scratch — the SBOM attestation turns "do we have the vulnerable library anywhere" from an emergency scan into a query.

---

## Bonus: Blob Signing (Codecov 2021 mitigation)

### Sign + verify
- Signed: `my-tool.tar.gz` + `my-tool.tar.gz.bundle`
- Verify-blob success output:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Verified OK
```

### Tamper test failed (correctly)
Appended `MALICIOUS PAYLOAD` to the "freshly downloaded" tarball and re-ran `cosign verify-blob` against the unchanged bundle/signature:
```
WARNING: Skipping tlog verification is an insecure practice that lacks transparency and auditability verification for the blob.
Error: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
error during command execution: failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature
```

### Codecov 2021 mitigation (2-3 sentences)
The Codecov bash uploader was fetched with `curl | bash` and executed immediately, with no step that could have detected the script had been silently modified on Codecov's own infrastructure. If Codecov had published a `cosign sign-blob` signature/bundle alongside every release of the uploader, and CI consumers had run `cosign verify-blob --key codecov.pub --bundle uploader.sh.bundle uploader.sh` before executing it (Lecture 8 slide 14), the attack would have failed at that verify step: the modified uploader's bytes wouldn't match the signature computed over the original, legitimate script, exactly as shown in the tamper test above, and the malicious script would never have reached `bash`.
