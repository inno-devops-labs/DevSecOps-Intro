# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
DefectDojo deployed locally via the official docker-compose stack (6 containers: nginx, uwsgi, postgres, valkey, celerybeat, celeryworker). Image: `defectdojo/defectdojo-django:latest`. Admin password retrieved from initializer logs (`docker compose logs initializer | grep -i password`).

### Product + Engagement
- Product ID: 1 — OWASP Juice Shop
- Engagement ID: 2 — Course Semester Run
- Engagement status: In Progress (CI/CD, target 2026-09-01 → 2026-12-15)

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 83 |
| 4 | Trivy Scan | trivy.json | 91 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 6 | Checkov Scan | checkov-terraform/results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 7 | Trivy Scan (image) | trivy-image.json | 47 |
| **Total raw imports** | | | **333** |

**Note on ZAP:** The Lab 5 ZAP report could not be imported. DefectDojo's ZAP parser rejected the JSON export ("Wrong file format, please use xml") and then threw an internal server error on the XML export (the report's empty `<site name="" host="">` field, produced because the scan targeted an IP rather than a hostname, breaks the parser). Six scan types imported successfully, meeting the ≥6 requirement.

### Cross-tool overlap / dedup example (Lecture 10 slide 11)
Comparing the CVE sets of the Grype test (id 13) and the Trivy test (id 14) shows **72 CVEs detected by both scanners** — a strong illustration of why a vulnerability-management system needs deduplication.

Concrete example — **CVE-2010-4756** (in package `libc6 2.41-12+deb13u2`):
- Finding id 389 — test 13 (Anchore Grype) — "CVE-2010-4756 in libc6:2.41-12+deb13u2"
- Finding id 423 — test 14 (Trivy Scan) — "CVE-2010-4756 Libc6 2.41-12+deb13u2"

The same CVE in the same package was reported independently by two tools. DefectDojo did not auto-collapse them because the engagement was imported with `deduplication_on_engagement: false` and the two parsers emit different `title` strings (`"in libc6:..."` vs `"Libc6..."`), so the dedup hash differs. Enabling deduplication in System Settings (hash based on CVE + component + version rather than title) would merge these into one finding — which is exactly the cross-tool consolidation DefectDojo exists to provide.

## Task 2: Governance Report

### SLA Configuration applied (Lecture 10 slide 8)
Default SLA configuration edited to the lab matrix and applied to the product:
| Severity | SLA |
|----------|-----|
| Critical | 1 day (24h) |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

### Executive Summary
OWASP Juice Shop, scanned with 5 tools across 6 scan imports (Grype, Trivy ×2, Semgrep, Checkov, KICS) yielding 333 raw findings, currently has 330 open findings (14 Critical + 144 High). Two Critical findings were remediated this period (MTTR ≈ 0 days — closed same day as detection in this baseline run), and one High was formally risk-accepted with an expiry date. As this is the program's first (baseline) import, all open findings are 0 days old and within SLA; time-based metrics become meaningful from the second cycle onward.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 14 |
| High | 144 |
| Medium | 150 |
| Low | 15 |
| Info | 7 |
| **Total active** | **330** |

### Findings by source tool
| Tool | Imported | Active | Mitigated | Risk Accepted |
|------|---------:|-------:|----------:|--------------:|
| Anchore Grype | 83 | 80 | 2 | 1 |
| Trivy (Lab 4) | 91 | 91 | 0 | 0 |
| Trivy image (Lab 7) | 47 | 47 | 0 | 0 |
| Semgrep | 22 | 22 | 0 | 0 |
| Checkov | 80 | 80 | 0 | 0 |
| KICS | 10 | 10 | 0 | 0 |
| **Total** | **333** | **330** | **2** | **1** |

### Program metrics
- **MTTD** (Mean Time to Detect): not measurable in a baseline import — all findings detected at import time (day 0).
- **MTTR** (Mean Time to Remediate): ≈ 0 days for the 2 closed findings (detected and mitigated on the same day in this baseline run). Real MTTR accrues once findings are closed across multiple days.
- **Vuln-age median** (open findings): 0 days (all imported today).
- **Backlog**: 330 active findings — this is the baseline measurement; future runs are compared against it.
- **SLA compliance**: 100% at baseline (no finding has yet exceeded its SLA window, since all were created today). The meaningful test is at the next cycle, when Critical findings older than 1 day would breach.

### Risk-accepted items (all must have expiry — Lecture 10 slide 12)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| #337 GHSA-35jh-r3h4-6jhm (lodash 2.4.2) | High | Dev-only transitive dependency, not reachable in production runtime; re-evaluate next quarter | 2026-09-26 |

### Next-quarter goal (OWASP SAMM practice)
Mature the **Defect Management** practice (Operations domain). Current state: 333 findings imported but only 2 triaged/closed and dedup not yet enabled, so the same CVE (e.g. CVE-2010-4756, found by both Grype and Trivy — 72 such overlaps) appears multiple times and inflates the backlog. Next quarter: (1) enable cross-tool deduplication keyed on CVE+component+version to collapse the 72 Grype/Trivy overlaps into single findings, and (2) add Falco runtime alerts as a custom-parser feed, so detection coverage spans build-time AND runtime in one backlog with one SLA clock.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: ~4 minutes 40 seconds read aloud
- Two anticipated Q&A questions covered: yes (Log4Shell response via SBOM; open-source vs IAST tradeoff)
- Strongest claim in the script: "72 CVEs found by both Grype and Trivy — that overlap is why dedup matters"