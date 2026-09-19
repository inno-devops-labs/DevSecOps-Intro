# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: `3069`
- `juice-shop.cdx.json` size: `1834859`
- `juice-shop.spdx.json` component count: `909`

### Grype severity breakdown (paste table or JSON)
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 51 |
| Medium | 35 |
| Low | 4 |
| Negligible | 7 |
| **Total** | 104 |

### Top 10 CVEs (paste from jq output)
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
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
7 of the top 10 findings have a fix available. Following Lecture 4's triage shortcut, we would sort by fix-available AND severity >= HIGH first, then put those seven Critical/High issues into the immediate patch queue because they are actionable now. The remaining three still need risk tracking or acceptance, but they should not block the fixable high-severity updates from moving quickly.

## Task 2: Trivy Comparison

### Side-by-side counts
| Severity | Grype | Trivy | Δ |
|----------|------:|------:|--:|
| Critical | 7 | 5 | -2 |
| High | 51 | 43 | -8 |
| Medium | 35 | 39 | +4 |
| Low | 4 | 22 | +18 |
| Negligible | 7 | 0 | -7 |
| **Total** | 104 | 109 | +5 |

### Why the difference?
- `CVE-2025-57349` — Trivy found it in `messageformat@2.3.0`; Grype did not report it. The likely reason is CVE database and ecosystem matching differences: Trivy mapped this Node package advisory to a CVE and fix version (`3.0.0-beta.0`), while Grype's SBOM-based result did not match that advisory for the same component set.
- `NSWG-ECO-428` — Trivy found this High issue in `base64url@0.0.6`; Grype did not report that advisory ID. This is a non-CVE Node Security Working Group advisory, so the difference is likely caused by advisory-source coverage rather than the package being absent from the SBOM.

After normalizing Grype's `GHSA-*` IDs to their related `CVE-*` IDs, there were no clear CVE-level findings that Grype found and Trivy missed. Most apparent Grype-only rows are the same vulnerability represented with a GitHub Security Advisory ID instead of the CVE ID Trivy shows.

### When would you pick each?
Syft+Grype's decoupled model wins when we need the SBOM as a durable artifact, not just a one-time scan result. One Syft SBOM can be stored, signed later as an attestation in Lab 8, and rescanned when new CVEs are published without rebuilding or re-pulling the image.

Trivy's all-in-one model wins when we want a simpler CI step with broad coverage. It can scan the image directly and also cover adjacent security checks like IaC, secrets, and misconfiguration, so it is easier to use as a quick pipeline gate.
