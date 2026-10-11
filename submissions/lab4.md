# Lab 4 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats
- `juice-shop.cdx.json` component count: 1846
- `juice-shop.cdx.json` size: 1504963 bytes (1.44 MB)
- `juice-shop.spdx.json` component count: 911

### Grype severity breakdown (paste table or JSON)
| Severity | Count |
|----------|------:|
| Critical | 7 |
| High | 52 |
| Medium | 36 |
| Low | 6 |
| Negligible | 7 |
| **Total** | 108 |

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
Out of the top 10 CVEs, 7 out of 10 have a fix available. This means we must prioritize fixing those vulnurabilities first, as they already have an immediate fix and are too critical to ignore. We can use Grype in a CI workflow and fail builds if high or critical CVEs with immediate fixes are detected (Slide 12 of the lecture).