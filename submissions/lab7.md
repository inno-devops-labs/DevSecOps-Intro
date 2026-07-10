# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 6 | 4 |
| High | 44 | 43 |
| **Total** | 50 | 47 |

### Top 10 CVEs with fixes
| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |
| NSWG-ECO-428 | HIGH | base64url | 0.0.6 | >=3.0.0 |
| CVE-2020-15084 | HIGH | express-jwt | 0.1.3 | 6.0.0 |
| CVE-2022-25881 | HIGH | http-cache-semantics | 3.8.1 | 4.1.1 |
| CVE-2022-23539 | HIGH | jsonwebtoken | 0.1.0 | 9.0.0 |
| NSWG-ECO-17 | HIGH | jsonwebtoken | 0.1.0 | >=4.2.2 |

### Compared to Lab 4's Grype scan
Look back at your Lab 4 Grype results on the same image. Pick **two CVEs**:
1. BOTH Grype and Trivy found a CVE in jsonwebtoken (CVE-2015-9235/GHSA-c7hr-j4mj-j2w6).
2. Grype found and Trivy missed a CVE in libc6 (CVE-2026-5450).

As mentioned in Lecture 4, "Grype and Trivy match installed deps against CVE DBs".
In the first case, both DBs had this vulnerability listed and thus produced the same result. Though despite that,
Grype used GitHub Advisory alias instead of the CVE index.
In the second case, only one of the DBs had the vulnerability listed probably due to database freshness.