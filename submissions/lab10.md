# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: `defectdojo/defectdojo-django:latest` (image id `c404a6c482ca`); compose stack run in **release** mode (`./docker/setEnv.sh release`) after `dev` entrypoints failed against the published image
- UI: http://localhost:8080 (nginx + uwsgi healthy)

### Product + Engagement
- Product ID: **1**
- Product name: OWASP Juice Shop
- Product type: Research and Development (`prod_type` 1)
- Engagement ID: **1**
- Engagement name: Course Semester Run
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | labs/lab4/grype-from-sbom.json | 107 |
| 4 | Trivy Scan | labs/lab4/trivy.json | 107 |
| 5 | Semgrep JSON Report | labs/lab5/results/semgrep.json | 22 |
| 5 | ZAP Scan | labs/lab5/results/auth-report.json | 0 (importer requires XML; JSON report also had 0 alerts) |
| 6 | Checkov Scan | labs/lab6/results/checkov-terraform/results_json.json | 80 |
| 6 | KICS Scan | labs/lab6/results/kics-ansible/results.json | 10 |
| 6 | KICS Scan | labs/lab6/results/kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | labs/lab7/results/trivy-image.json | 42 |
| 7 | Trivy Operator Scan | labs/lab7/results/trivy-k8s.json | 0 (k8s resource JSON ≠ Trivy Operator format) |
| 9 | Falco log | labs/lab9/falco/logs/falco.log | skipped (no stock Falco parser; documented per lab) |
| **Sum of successful import totals** | | | **374** (engagement finding count after Semgrep CE re-import) |
| **After dedup (duplicate flag)** | | | **0** auto-duplicates (`deduplication_on_engagement=false` on import); cross-tool same-CVE still visible as separate findings |

Notes:
- First importer run failed with product-type conflict (`Engineering` vs `Research and Development`); re-ran with `DD_PRODUCT_TYPE="Research and Development"`.
- Auto-discovered Semgrep type was **Semgrep Pro JSON Report** (0 findings); re-imported with **Semgrep JSON Report** → 22 findings.

### Dedup example (Lecture 10 slide 11)
- CVE/ID: **CVE-2018-20796** (`libc6:2.41-12+deb13u2`)
- Number of source tools: **2** — Anchore Grype (test 1) + Trivy Scan (test 2)
- DefectDojo finding IDs: **57** (Grype, Info) and **115** (Trivy, Low)

Same CVE also appears across Trivy lab4 (test 2) and Trivy lab7 image (test 8) for other titles (e.g. `CVE-2015-9235 Jsonwebtoken …`), which is the Lab 4↔7 SCA overlap pattern.

## Task 2: Governance Report

### SLA matrix applied
| Severity | SLA |
|----------|-----|
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

Applied in DefectDojo Configuration → SLA Configuration for this lab instance.

### Executive Summary
Juice Shop, scanned across 7 successful tool importers (Grype, Trivy×2, Semgrep, Checkov, KICS×2), currently has **373** open findings after one Risk Acceptance (**18 Critical + 148 High** at measurement time before RA; Critical/High remain the priority queue). Mean Time to Remediate (MTTR) on closed-this-period findings is **N/A** — **0** findings mitigated yet in this fresh capstone import. SLA compliance on closures is therefore also **N/A** until the first remediations land; the program’s immediate job is Critical/High triage under the 24h/7d clocks.

### Findings by severity 
| Severity | Count |
|----------|------:|
| Critical | 18 |
| High | 148 |
| Medium | 170 |
| Low | 29 |
| Info | 9 |
| **Total active (pre–risk-accept recount)** | **374** |

After Risk Acceptance of finding **57**, active count is **373** (1 risk-accepted).

### Findings by source tool
| Tool (test id) | Active | Mitigated | False Positive | Risk Accepted |
|----------------|-------:|----------:|---------------:|--------------:|
| Anchore Grype (1) | 106* | 0 | 0 | 1 (finding 57) |
| Trivy Scan lab4 (2) | 107 | 0 | 0 | 0 |
| Checkov Scan (5) | 80 | 0 | 0 | 0 |
| KICS ansible (6) | 10 | 0 | 0 | 0 |
| KICS pulumi (7) | 6 | 0 | 0 | 0 |
| Trivy Scan image (8) | 42 | 0 | 0 | 0 |
| Semgrep JSON Report (10) | 22 | 0 | 0 | 0 |
| ZAP / Trivy Operator / Semgrep Pro | 0 usable | — | — | — |

\*Grype was 107 active before RA; finding 57 moved to risk-accepted.

### Program metrics
- **MTTD** (Mean Time to Detect): **~0 days** — all imported findings share detect date `2026-07-17` (same-day pipeline import into DefectDojo).
- **MTTR** (Mean Time to Remediate): **N/A** — `is_mitigated=true` count = **0** in this engagement so far.
- **Vuln-age median** (open findings): **~0 days** (unique finding dates = `{2026-07-17}`).
- **Backlog trend**: **+374** vs empty baseline at engagement start (first load); next quarter should show falling Critical/High if remediations begin.
- **SLA compliance**: **N/A%** on closures (no mitigated findings yet). Going forward, track % of Critical closed ≤24h and High ≤7d.

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| #57 CVE-2018-20796 in libc6:2.41-12+deb13u2 (RA #1 `lab10-demo-libc-cve-2018-20796`) | Info (Grype) | Lab 10 governance demo — Info/Low glibc advisory accepted until next base-image rebuild | **2026-10-17** |

### Next-quarter goal 
Mature **Defect Management** (SAMM): today MTTR is undefined because nothing is closed yet and Critical+High alone are **166** items. Next quarter, set a High MTTR target of **≤7 days** (matching the SLA), wire automated import from CI (Grype/Trivy/Semgrep) on every main build, and add a Falco/custom parser so runtime alerts enter the same engagement instead of staying as orphan logs.
