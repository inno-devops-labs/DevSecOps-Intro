# Lab 8 — Software Supply Chain Security: Signing, Verification, and Attestations

## Task 1 — Local Registry, Signing, Verification, and Tamper Demo

### 1.1 Local registry flow

I pulled `bkimminich/juice-shop:v19.0.0`, started a local registry (`registry:3` on `localhost:5000`), tagged the image, and pushed it to:

`localhost:5000/juice-shop:v19.0.0`

Then I resolved the registry digest and signed by digest (not by tag):

- Original digest reference (`labs/lab8/analysis/ref.txt`):  
  `localhost:5000/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58`

Signing by digest is the key point: tags are mutable pointers, but digest is immutable content identity.

### 1.2 Signing and verification

I generated a local key pair with Cosign:

- `labs/lab8/signing/cosign.pub`
- `labs/lab8/signing/cosign.key` (private key, excluded from git)

Then I signed and verified the digest reference with Cosign.

Because Cosign v3 changed defaults around signing config/tlog flags, I used a local-lab compatible flow (`--use-signing-config=false` plus no tlog upload). Verification succeeded and produced valid signature claims in `labs/lab8/signing/cosign-verify.txt`.

### 1.3 Tamper demonstration

To simulate tag tampering:

1. I retagged `busybox:latest` as `localhost:5000/juice-shop:v19.0.0`.
2. I pushed it to the same tag.
3. I re-resolved the digest:
   - New digest (`labs/lab8/analysis/ref-after-tamper.txt`):  
     `localhost:5000/juice-shop@sha256:b8d1827e38a1d49cd17217efd7b07d689e4ea1744e39c7dcbb95533d175bea65`

Verification against the new digest failed as expected:

- `labs/lab8/analysis/verify-after-tamper.txt` shows `Error: no signatures found` with `exit_code=10`.

Verification against the original signed digest still succeeded:

- `labs/lab8/analysis/verify-original-after-tamper.txt`.

This demonstrates exactly why digest-based verification protects against tag tampering.

### 1.4 Image vulnerability/configuration scan evidence

#### Docker Scout

`labs/lab8/scanning/scout-cves.txt` reports:

- `12C / 72H / 36M / 6L / 13?`
- 1004 packages analyzed.

Top high-impact examples from Scout output:

1. `CVE-2026-22709` in `vm2` (Critical, CVSS 9.8, fixed in 3.10.2)
2. `CVE-2023-37903` in `vm2` (Critical, command injection)
3. `CVE-2023-37466` in `vm2` (Critical, code injection)
4. `CVE-2026-33937` in `handlebars` (Critical, fixed in 4.7.9)
5. `CVE-2026-33941` in `handlebars` (High, fixed in 4.7.9)

#### Snyk

`labs/lab8/scanning/snyk-results.txt` is present and captures an authentication failure (`SNYK-0005`, HTTP 401).  
So the command execution is documented, but valid Snyk vulnerability output requires a real `SNYK_TOKEN`.

#### Dockle

`labs/lab8/scanning/dockle-results.txt` captured findings such as:

- Missing `HEALTHCHECK` recommendation.
- Content trust recommendation (`DOCKER_CONTENT_TRUST=1`).
- Unnecessary files inside image filesystem.

These are configuration hygiene issues rather than CVEs, but still relevant to production hardening.

---

## Task 2 — Attestations (SBOM + Provenance)

### 2.1 SBOM attestation

I generated a Syft native SBOM and converted it to CycloneDX:

- `labs/lab4/syft/juice-shop-syft-native.json`
- `labs/lab8/attest/juice-shop.cdx.json`

Then I attached it as an attestation:

- Type: `cyclonedx`
- Verify output: `labs/lab8/attest/verify-sbom-attestation.txt`

I also decoded and inspected the attestation payload (base64 -> JSON):

- `labs/lab8/attest/sbom-attestation-payload-decoded.json`
- `labs/lab8/attest/sbom-attestation-payload-pretty.json`

### 2.2 Provenance attestation

I created a minimal provenance predicate and attached it as `slsaprovenance`:

- Predicate file: `labs/lab8/attest/provenance.json`
- Verify output: `labs/lab8/attest/verify-provenance.txt`

Decoded/pretty payload inspection:

- `labs/lab8/attest/provenance-payload-decoded.json`
- `labs/lab8/attest/provenance-payload-pretty.json`

From the payload we can clearly see:

- subject image name and digest,
- builder ID,
- build type,
- invocation parameters (including image reference),
- build timestamp metadata.

### 2.3 Signatures vs attestations (short analysis)

- **Image signature** proves integrity and signer identity for a specific subject digest.
- **Attestation** carries signed metadata *about* that digest (SBOM contents, provenance facts, build context).

So signatures answer “is this exact image signed by the expected key?”, while attestations answer “what do we know about this image and its build/materials?”.

---

## Task 3 — Blob/Tarball Signing

I created a non-container artifact:

- `labs/lab8/artifacts/sample.txt`
- `labs/lab8/artifacts/sample.tar.gz`

Then I signed and verified it with Cosign bundle flow:

- Sign output: `labs/lab8/artifacts/sign-blob.txt`
- Bundle: `labs/lab8/artifacts/sample.tar.gz.bundle`
- Verify output: `labs/lab8/artifacts/verify-blob.txt` (`Verified OK`)

This demonstrates signing for non-container assets (release archives, config bundles, policy packs, etc.).

### Blob signing vs image signing

- **Blob signing** signs a local file digest directly and can be verified offline with key + signature/bundle.
- **Image signing** signs OCI references in a registry ecosystem (image manifests, tags/digests, referrers/attachments).

Both rely on the same cryptographic trust model, but image signing is registry-aware and supply-chain oriented by default.

---

## CIS Docker Benchmark Snapshot

`labs/lab8/hardening/docker-bench-results.txt` contains benchmark output with a mix of PASS/WARN/INFO.

Examples of flagged concerns:

- No separate container partition (`[WARN] 1.1`)
- Missing audit controls (`[WARN] 1.5`, `1.6`)
- No TLS auth for daemon (`[WARN] 2.6`)
- User namespace support not enabled (`[WARN] 2.8`)
- Content trust and healthcheck recommendations (`[WARN] 4.5`, `4.6`)

On a local desktop this is common, but in production these warnings should be treated as hardening backlog items.

---

## Short Conclusions

1. Digest-based Cosign signing/verification worked end-to-end in a local insecure registry setup.
2. Tag tampering was demonstrated successfully: new digest fails verification, original digest remains valid.
3. SBOM and provenance attestations were both attached, verified, and payload-inspected.
4. Non-container blob signing/verification worked with bundle output.
5. Docker Scout and Docker Bench gave actionable vulnerability/hardening signals; Snyk run was captured but requires valid token for full results.

