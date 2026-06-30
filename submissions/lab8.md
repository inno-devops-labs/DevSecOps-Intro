# Lab 8 — Submission

> Lab 8 complete (Task 1 + Task 2). Bonus optional.

---

## Task 1: Sign + Tamper Demo

### Registry + image push

- Registry container: `lab8-registry` on `localhost:5000`
- Image pushed: `localhost:5000/juice-shop:v20.0.0`
- Image digest:

```
localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d
```

### Signing

`cosign sign` succeeded (keyed sign with `labs/lab8/keys/cosign.key`, `COSIGN_PASSWORD=lab8`, `--allow-insecure-registry`).

### Verification (PASSED)

```json
[{"critical":{"identity":{"docker-reference":"localhost:5000/juice-shop@sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"image":{"docker-manifest-digest":"sha256:8c76bce948965bcb2ad33c24a659d58f307d679ff48ec253a3d29138329f3c0d"},"type":"https://sigstore.dev/cosign/sign/v1"},"optional":{}}]
```

Checks: cosign claims validated; signatures verified against `cosign.pub`.

### Tamper Demo (FAILED — correctly)

```
WARNING: Skipping tlog verification is an insecure practice...
Error: no signatures found
error during command execution: no signatures found
```

Alpine re-tag digest has **no** Cosign signature bound to it — tamper detection works.

### Sanity — original still verifies

Same JSON as initial verify — original digest `sha256:8c76bce...` still passes after tamper attempt.

### Why digest binding matters (Lecture 8 slide 6)

Cosign binds the signature to the **image digest** (`sha256:8c76bce...`), not the tag `v20.0.0`. Re-tagging alpine as `juice-shop` produces a **different digest**; verify fails because the signature covers only the original Juice Shop manifest bytes. If Cosign signed the **tag** instead, a registry could point `v20.0.0` at malicious content while the old signature still appeared valid — digest binding prevents tag-swapping attacks.

---

## Task 2: SBOM + Provenance Attestations

### SBOM attestation

- Attached: **yes** (`cosign attest --type cyclonedx` exit 0)
- Predicate source: `labs/lab4/juice-shop.cdx.json` (regenerated with Syft on Kali)
- Component count: **3069** (`jq '.components | length'`)
- `cosign verify-attestation --type cyclonedx`: **passed** (output includes `CycloneDX`)

```text
Verification for localhost:5000/juice-shop@sha256:8c76bce...
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key
CycloneDX
```

Image now has two artifacts in registry: **cosign signature** (`sign/v1`) + **CycloneDX attestation** (`cyclonedx.org/bom`).

### Provenance attestation

- Attached: **yes** (`cosign attest --type slsaprovenance` exit 0, without `--tlog-upload=false`)
- Builder ID: `https://localhost/lab8-student`
- buildType: `https://example.com/lab8/local-build`
- `cosign verify-attestation --type slsaprovenance`: **passed**

```json
{"payloadType":"application/vnd.in-toto+json","predicateType":"https://slsa.dev/provenance/v0.2","predicate":{"builder":{"id":"https://localhost/lab8-student"},"buildType":"https://example.com/lab8/local-build","invocation":{"configSource":{"uri":"https://github.com/Nopef/DevSecOps-Intro","digest":{"sha1":"abc123"}}}}}
```


Registry now holds **three** cosign artifacts: image signature (`sign/v1`), CycloneDX SBOM (`cyclonedx.org/bom`), SLSA provenance (`slsa.dev/provenance/v0.2`).

### What this gives a Lab 9 verifier

A **signed-only** image proves identity (who published this digest) but not **what is inside**. A **signed + CycloneDX attestation** image lets admission policy (Kyverno `verifyImages`) require the SBOM predicate and answer “was `log4j` in this image at deploy time?” without re-scanning. When the next Log4Shell-style CVE drops, security can query the **attested BOM** from the registry instead of trusting tags or rebuilding SBOM from scratch.

---
