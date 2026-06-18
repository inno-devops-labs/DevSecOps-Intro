# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 3069
- `juice-shop.cdx.json` size: 1834867
- `juice-shop.spdx.json` component count: 909

### Grype severity breakdown (paste table or JSON)
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 50 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 103 |

### Top 10 CVEs (paste from jq output)
| CVE | Severity | Package | Installed Version | Fix Version |
|-----|----------|---------|-------------------|-------------|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 | No fix available |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| GHSA-5mrr-rgp6-x4gr | Critical | marsdb | 0.6.11 | No fix available |
| GHSA-35jh-r3h4-6jhm | High | lodash | 2.4.2 | 4.17.21 |
| GHSA-8hfj-j24r-96c4 | High | moment | 2.0.0 | 2.29.2 |
| GHSA-p6mc-m468-83gw | High | lodash.set | 4.3.2 | No fix available |

### Fix-available rate
Out of the top 10 CVEs, how many have a fix available? What does that say about your
patch cadence priorities? (2-3 sentences. Reference Lecture 4's triage shortcut:
*sort by fix-available AND severity ≥ HIGH first*.)

Patch those 7 first — they're quick wins with immediate risk reduction. The 3 without fixes (libc6, marsdb, lodash.set) need deeper investigation but come after the actionable ones.

## Task 2: Trivy Comparison

### Side-by-side counts

| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 3 | 43 | +40 |
| Medium | 0 | 39 | +39 |
| Low | 0 | 22 | +22 |
| **Total** | 10 | 109 | +99 |

### Why the difference?

1. CVE-2026-45447 (libssl3t64) — Trivy found, Grype missed
    - Different database refresh cadences. Trivy updates daily; this is a recent 2026 CVE that Trivy caught but Grype hasn't yet.

2. Private keys — Trivy found 2 (insecurity.js + insecurity.ts), Grype missed
    - Grype is vulnerability-only; Trivy includes **secret scanning** as part of its all-in-one scanner.

Trivy found 99 more vulnerabilities + 2 secrets because it scans **every node module** (109+ packages) while Grype focuses on top-level dependencies, and Trivy includes secrets and misconfigurations.

### When would you pick each?

Syft+Grype decoupled model wins when:
    - You need SBOM-as-attestation — generate SBOM once at build, sign it, then scan later against updated DBs without re-analyzing the image. Great for compliance (SLSA) and supply chain audits.

Trivy all-in-one wins when:
    - You want one simple CI step that scans vulnerabilities + secrets + misconfigurations. Faster setup, broader coverage — as seen with private key detection that Grype completely missed.
