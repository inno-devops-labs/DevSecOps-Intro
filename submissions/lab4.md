# Lab 4 — Submission

## Task 1

### Component counts

| Field | Value |
|-------|-------|
| CycloneDX components (`jq '.components \| length'`) | `3068` |
| SPDX packages (`jq '.packages \| length'`) | `909` |
| CycloneDX `specVersion` | `1.7` |

**Why the counts differ.** CycloneDX lists every single resolved dependency — including all the transitive npm packages, runtime deps, and OS-layer packages — so each one becomes its own `component`. SPDX groups things that share the same provenance under one package entry, which is closer to "installed software" from a human perspective. That's why the same image gives ~3× more entries in CycloneDX than in SPDX: the npm tree alone has hundreds of transitive packages that CycloneDX splits out one by one.

### Severity table (Grype, from SBOM)

| Severity | Count |
|----------|-------|
| Critical | 14 |
| High | 84 |
| Medium | 60 |
| Low | 12 |
| Negligible | 7 |
| Unknown | 4 |
| **Total** | **181** |

### Top 10 findings (ranked by severity)

| Severity | ID | Package @ version | Fix |
|----------|----|-------------------|-----|
| Critical | GHSA-c7hr-j4mj-j2w6 | `jsonwebtoken@0.1.0` | 4.2.2 |
| Critical | GHSA-c7hr-j4mj-j2w6 | `jsonwebtoken@0.4.0` | 4.2.2 |
| Critical | GHSA-jf85-cpcp-j695 | `lodash@2.4.2` | 4.17.12 |
| Critical | CVE-2026-63073 | `libssl3t64@3.5.5-1~deb13u2` | 3.5.7-1~deb13u2 |
| Critical | GHSA-mp2f-45pm-3cg9 | `decompress@4.2.1` | *(no fix)* |
| Critical | GHSA-xwcq-pm8m-c4vf | `crypto-js@3.3.0` | 4.2.0 |
| Critical | GHSA-23hp-3jrh-7fpw | `tar@4.4.19` | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | `tar@6.2.1` | 7.5.19 |
| Critical | GHSA-23hp-3jrh-7fpw | `tar@7.5.15` | 7.5.19 |
| Critical | CVE-2026-5450 | `libc6@2.41-12+deb13u2` | *(no fix)* |

8 out of 10 have a fix available. I'd start with `jsonwebtoken` — two Critical entries, fix is just a version bump to 4.2.2, and JWT is in the auth path so the impact is high. After that `lodash` and `crypto-js` are also Critical with fixes ready. `decompress` and `libc6` are Critical but have no fix yet, so I'd just watch those for now.

---

## Task 2

### Severity table — Grype vs. Trivy

| Severity | Grype | Trivy | Delta |
|----------|-------|-------|-------|
| Critical | 14 | 10 | −4 |
| High | 84 | 64 | −20 |
| Medium | 60 | 66 | +6 |
| Low | 12 | 31 | +19 |
| Negligible | 7 | — | — |
| Unknown | 4 | — | — |
| **Total** | **181** | **171** | — |

Unique advisory IDs: Grype found 155, Trivy found 144. 104 IDs appear only in Grype, 93 only in Trivy, 51 in both.

### Divergent findings

**Grype found, Trivy missed — `CVE-2026-48617` (`node@24.15.0`, binary)**  
Grype detects the embedded Node.js runtime as a binary component and matches it against the Node.js advisory feed. Trivy works from package manifests (`package.json`) and OS databases, so an unpackaged binary sitting in the image has nothing for it to match against — it just doesn't show up.

**Trivy found, Grype missed — `CVE-2015-9235` (`jsonwebtoken@0.1.0`, npm)**  
This is an old 2015 NVD entry for a JWT algorithm-confusion issue. Grype already reported the same vulnerability under its GHSA alias (`GHSA-c7hr-j4mj-j2w6`) and treats that as the canonical ID, so the raw CVE-ID never appears separately. Trivy pulls the NVD ID and the GHSA alias independently and lists both — not really a different finding, just different advisory-source handling.

### Decoupled inventory vs. all-in-one scanner

The SBOM approach makes sense when you need to re-scan without re-pulling the image — if a new CVE drops next week, I can just run Grype against the stored JSON file in seconds. It also matters for Lab 8, which attaches this exact CycloneDX file to the image as a signed attestation, so someone downstream can verify what was in the image at build time. Trivy as a single binary is easier when I just need a quick pass/fail answer in CI: one command, no artifact to keep around. The tradeoff is losing the re-scan ability and the signed SBOM chain.

---

## Bonus

### jq command used

```bash
jq -n \
  --slurpfile pred labs/lab4/juice-shop.cdx.json \
  '{
    "_type": "https://in-toto.io/Statement/v0.1",
    "subject": [{
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {"sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"}
    }],
    "predicateType": "https://cyclonedx.org/bom",
    "predicate": $pred[0]
  }' > labs/lab4/juice-shop-attestation.json
```

### First 20 lines of the result

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "serialNumber": "urn:uuid:cae9bb5d-3d17-439e-8cd9-f83438d171e5",
    "version": 1,
    "metadata": {
```

### Digest

`fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

The digest is used instead of the tag because tags are mutable — someone could push a different image under `v20.0.0` at any point and the tag would just point to the new one. The SHA-256 digest is tied to the exact bytes of the manifest, so the signature always refers to the specific image that was actually scanned.

### What this file claims, who checks it, what it does not prove

The file says: "this image (identified by digest) contains the components listed in this CycloneDX SBOM." A CI policy engine or `cosign verify-attestation` would check it to confirm that a signed SBOM exists for the image before allowing it to run. What it doesn't prove is that the SBOM is complete or accurate — it only guarantees that whatever Syft produced hasn't been tampered with. It also doesn't prove that the vulnerabilities found by Grype were actually fixed.
