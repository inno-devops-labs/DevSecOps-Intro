# Lab 10 — Vulnerability Management: The Capstone

DefectDojo **2.58.3**, one product (*OWASP Juice Shop*) / one engagement (*Course Semester Run*), loaded from the Lab 4–7 scan outputs via `run-imports.sh` plus a hand-imported ZAP XML.

## Task 1

### Imported reports, parser, and finding count
| Lab | File | Parser (scan_type) | Active findings |
|-----|------|--------------------|----------------:|
| 4 | `grype-from-sbom.json` | Anchore Grype | 183 |
| 4 | `trivy.json` | Trivy Scan | 173 |
| 5 | `semgrep.json` | Semgrep JSON Report | 27 |
| 5 | `auth-report.xml` | ZAP Scan | 13 |
| 6 | `checkov-terraform/results_json.json` | Checkov Scan | 80 |
| 6 | `kics-ansible/results.json` | KICS Scan | 10 |
| 6 | `kics-pulumi/results.json` | KICS Scan | 6 |
| 7 | `trivy-image.json` | Trivy Scan | 85 |
| 7 | `trivy-k8s.json` | Trivy Operator Scan | 0 |

> **Parser gotcha:** the importer first tried Lab 5's `auth-report.json` and DefectDojo's *ZAP Scan* parser rejected it — `Wrong file format, please use xml`. DefectDojo 2.58 only parses ZAP's **XML** report, not the traditional-json one. I re-ran the authenticated ZAP scan with a `traditional-xml` report job and imported `auth-report.xml` (13 findings). Trivy-operator (`trivy-k8s.json`) imported cleanly but contributed **0** findings — the hardened namespace had no HIGH/CRITICAL misconfigurations, exactly the Lab 7 result.

### Active findings by severity
| Severity | Count |
|----------|------:|
| Critical | 36 |
| High | 249 |
| Medium | 232 |
| Low | 47 |
| Info | 13 |
| **Total active** | **577** |

### Two duplicate titles — double-count or separate?
- **`Secret Management: Passwords and Secrets - Generic Password` ×7** → **seven separate findings.** KICS flagged seven distinct hardcoded secrets at seven different file/line locations in the Ansible playbooks; each has its own location, so these are seven real issues sharing one rule, not one issue counted seven times. Decided by: distinct `file_path`/line per finding.
- **`CVE-2015-9235` (vulnerable `jsonwebtoken`)** → **one issue counted twice.** It appears under both *Anchore Grype* (test 1) and *Trivy Scan* (test 2) because the same package vulnerability was reported by two scanners imported as separate tests, and cross-tool dedup was not enabled on import. This is systematic: **142 CVE ids overlap between the Grype and Trivy image scans**, so a large slice of the 249 "High" is the same packages counted twice. Decided by: identical CVE id + same package across two `scan_type`s.

### Which labs I'd act on this week, and which are noise
I'd act on **Lab 5 first**: the SQL injection on `/rest/products/search` is the one finding corroborated from two directions — Semgrep in the source *and* ZAP against the running app — so it's real and exploitable, not theoretical. Then the **Lab 4/7 Critical SCA findings that have a fix** (crypto-js, jsonwebtoken, lodash, tar) — one-line dependency bumps with the highest impact-to-effort — and the **Lab 6 wildcard-IAM policy** (`Action:"*" Resource:"*"`), a single resource clearing four rules. The **noise** this week is the cross-tool duplication (142 CVEs double-reported by Grype+Trivy inflate the High count), the many base-OS CVEs with **no fix available**, the Semgrep hits inside `data/static/codefixes/` teaching snippets, and KICS's `Unpinned Package Version` Low — all real-ish but none actionable this sprint.

## Task 2

### SLA: mine vs the defaults
| Severity | Default (days) | Mine (days) | Why |
|----------|---------------:|------------:|-----|
| Critical | 7 | **3** | Critical here means a fixable, often network-reachable RCE/injection or a KEV-class CVE; 3 days forces it into the current week, not next. |
| High | 30 | **14** | A month lets a High rot across a whole sprint boundary; two weeks keeps it inside one sprint. |
| Medium | 90 | **60** | 90 days is effectively "someday"; 60 still fits a quarter but creates real pressure. |
| Low | 120 | **90** | Low should still age out within a quarter so the backlog can't grow unbounded. |

### Active findings by severity and by source tool
By severity: Critical 36 · High 249 · Medium 232 · Low 47 · Info 13 (total **577**).
By tool: Anchore Grype 183 · Trivy Scan (image, Labs 4+7) 258 · Checkov 80 · Semgrep 27 · ZAP 13 · KICS 16 · Trivy Operator 0.

### Three numbers, with method
- **Median age of active findings: 0 days.** `GET /findings/?active=true` → `[.age] | sort | median`. Every finding entered DefectDojo today in a single capstone import, so the system has no real age history yet — in a running program these would carry their discovery dates across the semester. (Oldest below is the same story.)
- **Oldest active finding: 0 days.** `max([.age])` over the same set.
- **Share inside SLA: 564 of 577 (97.7%), 0 breached.** `GET /findings/?active=true` → count `sla_days_remaining >= 0`; the 13 ZAP findings return `null` (no SLA clock computed for that parser's findings), and nothing is past due because age is 0. The honest reading: SLA compliance is trivially 100% today and only becomes meaningful once the clock has run.

### What Labs 8 and 9 produced that these numbers miss
None of the 577 include **Lab 8's cosign signatures/SBOM attestations** (supply-chain integrity) or **Lab 9's Falco runtime alerts and Conftest policy results** — DefectDojo ships no parser for cosign verification output or Falco JSON. I'd track those as separate controls: file the Falco detections through DefectDojo's **generic findings JSON** importer (or route them to a SIEM), and record signing/attestation status in the engagement as a control checklist, so "is it signed" and "did it do something at runtime" aren't invisible just because they aren't CVEs.

### Risk acceptance
`decompress@4.2.1` — **GHSA-mp2f-45pm-3cg9 (Critical), no fix available.** Risk-accepted until **2026-12-15** (semester end), compensating controls: the package is not reachable on any network-exposed path in our deployment, and the Lab 7 hardening (read-only root FS, dropped capabilities, default-deny egress NetworkPolicy) contains what an exploit could do. Re-evaluated at expiry or when a fixed version ships, whichever is first.

### Executive summary
The project has a single consolidated view of 577 active findings across SCA, SAST, DAST, IaC and container scanning, but roughly half the High count is the same CVEs double-reported by two overlapping image scanners, so the true backlog is smaller than it looks. The single biggest risk is the **confirmed SQL injection on the product-search endpoint**, the only finding proven exploitable at runtime (ZAP) and in source (Semgrep). To close it I need one developer-sprint to parameterise the two raw SQL queries and bump the handful of fixable Critical dependencies — everything else can wait behind that.

## Bonus
See `submissions/lab10-walkthrough.md`. The hardest part to explain concisely was **why "577 findings" is almost the wrong number** — the whole cross-tool-deduplication story (142 CVEs counted twice, no-fix vs fixable, teaching-snippet noise) takes longer to say than the headline figure, yet it's the part that makes the headline honest. That tells me the next project should record *decisions and dedup rules alongside the raw counts from day one*, so the defensible number — not the raw one — is what's on the slide.
