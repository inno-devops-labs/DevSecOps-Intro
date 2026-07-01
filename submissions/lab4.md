# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 910
- `juice-shop.cdx.json` size: ~2.1 MB
- `juice-shop.spdx.json` component count: 910

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 52 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 105 |

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|---|---|---|---|---|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 |  |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 |  |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 |  |

### Fix-available rate
Out of the top 10 Critical/High CVEs, 7 have immediate fixes available, while 3 (like `marsdb` and `libc6`) do not. This proves the triage shortcut from Lecture 4: sorting purely by severity is inefficient. Patching priorities must focus on `severity >= HIGH AND fix-available == true` to actually reduce risk, while the unpatchable ones require compensating controls (like WAF rules or network isolation).

---

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 52 | 43 | -9 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| **Total** | 105 | 109 | +4 |

### Why the difference?
1. **GHSA-5mrr-rgp6-x4gr (marsdb)**: Found by Grype, missed by Trivy. Grype scans the Syft-generated SBOM, which aggressively catalogs deeply nested or abandoned Node.js packages (like `marsdb` 0.6.11). Trivy's direct image scan sometimes filters out packages if its vulnerability database (which relies heavily on active vendor feeds) considers the exploit path unreachable or the package context irrelevant.
2. **OS-level Low/Medium CVEs (e.g., in Debian utilities)**: Found more by Trivy (22 Low vs Grype's 4). Trivy is notoriously strict about OS-level packages and pulls deeply from Debian's security tracker, flagging minor issues in base image utilities (like `coreutils` or `bash`) that Grype often ignores or classifies differently based on NVD scoring.

### When would you pick each?
- **Syft+Grype (Decoupled):** Wins in supply chain security and compliance. You generate the SBOM once during the build, sign it as an artifact (attestation), and can re-scan that same SBOM months later without needing access to the heavy container image.
- **Trivy (All-in-one):** Wins in CI/CD pipelines for fast, blocking checks. It's a single binary that scans OS packages, language dependencies, IaC, and secrets all at once, making it much easier to drop into a GitHub Action without managing intermediate files.

---

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: 1.5
- `bomFormat`: CycloneDX

### Image digest captured
- `docker inspect ... RepoDigests`: `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate
```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "bkimminich/juice-shop:v20.0.0",
      "digest": {
        "sha256": "fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0"
      }
    }
  ],
  "predicateType": "https://cyclonedx.org/bom/v1.5",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.5"

```

### What this enables in Lab 8

When Lab 8 runs cosign attest --type cyclonedx --predicate juice-shop-attestation.json ..., it cryptographically binds this CycloneDX SBOM (the predicate) to the specific image digest (the subject) using our private key. This proves the claim: "I, the author, verify that this specific build of the image contains exactly these components," preventing tampering in the supply chain and answering the "Log4Shell question" with verified evidence.