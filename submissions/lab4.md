# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: **1846**
- `juice-shop.cdx.json` size: **1,504,963 bytes** (~1.5 MB)
- `juice-shop.spdx.json` component count: **911**

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 52 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | **105** |

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-23c5-xmqv-rm74 | High | minimatch | 3.0.5 | 3.1.4 |
| GHSA-869p-cjfg-cm3x | High | jws | 0.2.6 | 3.2.3 |
| CVE-2026-5435 | High | libc6 | 2.41-12+deb13u2 | |

### Fix-available rate
**7 of 10** top findings have a published fix version. Per Lecture 4 triage: patch **Critical/High with fixes first** (openssl/libssl, lodash, jsonwebtoken, minimatch) before spending time on unfixed base-image issues like `libc6`/`marsdb`. The SBOM makes it obvious which Juice Shop npm dependencies are dragging in known-vulnerable versions.

---

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | −2 |
| High | 52 | 43 | −9 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | −7 |
| **Total** | **105** | **109** | **+4** |

### Why the difference?
1. **CVE-2026-34182** (libssl3t64) — **Grype found, Trivy missed** on this run. Likely different Debian/openssl matching rules and DB refresh timing between Anchore and Aqua databases.
2. **CVE-2015-9235** (jsonwebtoken) — **Trivy found, Grype reported GHSA-c7hr-j4mj-j2w6** for the same library. Same underlying flaw, different ID namespace (CVE vs GitHub Advisory); tools don't always normalize aliases identically.

### When would you pick each?
- **Syft + Grype (decoupled):** when you need a durable SBOM artifact you can re-scan after new CVEs drop, attach as a Cosign attestation (Lab 8), and feed into DefectDojo without re-pulling the image.
- **Trivy (all-in-one):** when you want one CI step for image vulns + misconfig + secrets with minimal plumbing; great for fast gatekeeping, less ideal as a long-lived signed inventory document.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: **1.5**
- `bomFormat`: **CycloneDX**

### Image digest captured
- `docker inspect bkimminich/juice-shop:v20.0.0 --format '{{index .RepoDigests 0}}'`:
  `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate (first lines)
```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": { "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0" }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": { "bomFormat": "CycloneDX", "specVersion": "1.5", "components": [ "...1846 components..." ] }
}
```

### What this enables in Lab 8
`cosign attest --type cyclonedx --predicate juice-shop-attestation.json` signs an in-toto statement binding the **image digest** to the **CycloneDX BOM contents**. The claim: *at build/deploy time, this exact image contained exactly these packages*. Consumers (registry, CI, auditors) can verify the signature and compare the attested SBOM against fresh Grype/Trivy results during incident response (Log4Shell-style dependency tracing).
