# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3069 (CycloneDX 1.7)
- `juice-shop.cdx.json` size: 1.8 MB
- `juice-shop.spdx.json` package count: 909 (SPDX)
- Note: Grype 0.107.0 does not support CycloneDX 1.7, so a 1.5-converted SBOM was used for SBOM-input scanning

### Grype severity breakdown
| Severity | Count |
|----------|------:|
| Critical | 8 |
| High | 51 |
| Medium | 37 |
| Low | 6 |
| Negligible | 7 |
| **Total** | **109** |

### Top 10 CVEs
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| GHSA-mp2f-45pm-3cg9 | Critical | decompress | 4.2.1 | — |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | — |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | — |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |

### Fix-available rate
Out of the top 10 CVEs, 6 out of 8 Critical have a fix available, while 2 have no fix (decompress and marsdb — both abandoned packages). This confirms Lecture 4's triage shortcut: prioritize by fix-available AND severity ≥ HIGH first. The abandoned packages (decompress, marsdb) are riskier because no patch will ever come — they require replacement, not upgrade. Fix-available CVEs should be patched immediately in the next CI run.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 8 | 6 | -2 |
| High | 51 | 43 | -8 |
| Medium | 37 | 40 | +3 |
| Low | 6 | 22 | +16 |
| Negligible | 7 | 0 | -7 |
| **Total** | **109** | **111** | **+2** |

### Why the difference?
1. **CVE-2026-5450 (libc6, Critical)** — Grype found it, Trivy missed it. Likely because Grype's DB had a newer refresh cycle for the Debian 13 (trixie) package feed. Trivy's DB snapshot was older and may not have indexed this CVE yet.

2. **CVE-2023-46233 (crypto-js, Critical)** — Trivy found it as a CVE, while Grype reported the same vulnerability as GHSA-xwcq-pm8m-c4vf. Different DB vendors (NVD vs GitHub Advisory Database) assign different IDs for the same underlying flaw. Trivy's DB maps to NVD CVEs, while Grype uses GHSA as primary.

### When would you pick each?
- **Syft+Grype's decoupled model** wins when you need audit-grade SBOMs: the SBOM is signed once (Lab 8), then re-scanned repeatedly without re-pulling the image. This is crucial for incident response — when a new CVE drops, re-scan the committed SBOM in seconds. It also enables multi-tool scanning (Grype + Trivy + others) from a single inventory.

- **Trivy's all-in-one** wins when simplicity and speed matter in CI: one binary, one command, one output. It covers not just OS/npm vulns but also IaC misconfigs, secrets, and Kubernetes scanning — all from the same tool. For a quick CI gate that says "ship or block?", Trivy is the simplest choice.

## Bonus: Sign-Ready SBOM for Lab 8

### CycloneDX schema version
- `specVersion`: "1.7"
- `bomFormat`: "CycloneDX"

### Image digest captured
- `docker inspect ... RepoDigests`: `bkimminich/juice-shop@sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`

### Attestation predicate (first 30 lines)
```
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
  "predicateType": "https://cyclonedx.org/bom/v1.7",
  "predicate": {
    "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    ...
```

### What this enables in Lab 8
When Lab 8 runs `cosign attest --type cyclonedx --predicate juice-shop-attestation.json ...`, it signs the entire SBOM as an in-toto attestation. This cryptographically binds the SBOM (the full inventory of dependencies) to the container image digest. The claim being proved is: "this specific image (identified by its sha256 digest) contained exactly these dependencies at build time." Any future tampering with the SBOM or the image breaks the signature, providing a verifiable chain of custody from build to deployment.