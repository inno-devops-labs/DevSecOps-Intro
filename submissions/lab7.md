# Lab 7 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown
| Severity | Total | With fix available |
|----------|------:|------------------:|
| Critical | 5 | 4 |
| High | 43 | 42 |
| **Total** | 48 | 46 |

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
1. One that BOTH Grype and Trivy found
**CVE found by BOTH tools: CVE-2019-10744 (lodash prototype pollution)**
Trivy flagged this in the Lab 7 scan as CRITICAL (lodash 2.4.2 → fix 4.17.12).
Grype independently found the same underlying lodash prototype-pollution issue
in Lab 4 (listed there as GHSA-jf85-cpcp-j695, Critical, same installed/fix
versions). Both tools agree here because this is a long-standing, heavily
cited vulnerability that's present in essentially every vulnerability feed
(NVD, GHSA, OSV) both scanners' DBs ingest — old, well-documented CVEs tend
to have near-universal coverage regardless of scanner choice.
2. One that ONE tool found and the OTHER missed
For each: explain why the tools differ (DB freshness? Different package matching?
EPSS scoring? Lecture 7 + Lecture 4 give context.) (2-3 sentences per CVE.)
**CVE found by ONE tool, missed by the other: CVE-2026-45447 (libssl3t64) vs CVE-2026-5450 (libc6)**
Trivy's Lab 7 scan surfaced CVE-2026-45447 (libssl3t64, HIGH, OpenSSL
heap-use-after-free, fix 3.5.6-1~deb13u2) — a Debian OS-package finding.
Grype's Lab 4 scan, by contrast, surfaced a different Debian OS CVE,
CVE-2026-5450 (libc6, CRITICAL, marked "won't fix"), which does not appear
anywhere in the Lab 7 Trivy output. This is a DB freshness / advisory-source
gap: Trivy and Grype pull Debian security advisories from different feeds
(Trivy uses the Debian Security Tracker + its own aggregated DB; Grype uses
OSV/NVD-derived data) that get updated on different schedules, so a given
scan date can show one tool aware of a just-published advisory the other
hasn't ingested yet — and vice versa.

