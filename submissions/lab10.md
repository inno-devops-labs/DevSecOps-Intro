# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: defectdojo/defectdojo-django:latest

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 108 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | zap-report-auth.json | 0 (import failed — format mismatch) |
| 6 | Checkov Scan | results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| **Total raw imports** | | | 276 |
| **After dedup (engagement total)** | | | 276 |

### Dedup example (Lecture 10 slide 11)
The raw import counts sum to 276 and the engagement total is also 276 — DefectDojo's automatic
deduplication collapsed **zero** findings (`?duplicate=true` returns 0). This is itself the
instructive result: Grype and Trivy detect the **same** vulnerability but report it under
**different identifiers**, so DefectDojo's hash-based dedup does not merge them.
- Example issue: the crypto-js weak-PBKDF2 vulnerability in `crypto-js:3.3.0`
- Grype's finding: `GHSA-xwcq-pm8m-c4vf in crypto-js:3.3.0` — **finding ID 25**
- Trivy's finding: `CVE-2023-46233 Crypto-Js 3.3.0` — **finding ID 111**
- Number of source tools: **2** (Anchore Grype + Trivy) — the same flaw in the same package/version,
  but GHSA vs CVE naming (and different title casing) produced two separate findings instead of one
  deduplicated entry.
- Lesson: effective cross-tool dedup requires identifier normalization (mapping GHSA↔CVE). Without
  it, the ideal of "the same CVE from N tools collapsing into one finding" does not hold — 276 raw
  findings remained 276 after dedup, and ID 25 / ID 111 are the concrete proof.

## Task 2: Governance Report

### SLA matrix (10.7)
DefectDojo SLA Configuration id 1 ("Default") matches the Lecture 9/10 matrix and is inherited by
the engagement: Critical 1 day (24h) · High 7 days · Medium 30 days · Low 90 days. Confirmed on
findings — e.g. a High finding shows `sla_days_remaining: 7`, `sla_expiration_date: 2026-07-17`
(exactly 7 days from import).

### Executive Summary
Juice Shop, scanned across 6 tools, currently has 271 open findings (8 Critical + 119 High). Three
Critical findings were remediated this period (crypto-js, lodash, jsonwebtoken — all had upstream
fixes), and two no-fix Criticals (decompress, marsdb) were formally risk-accepted with a Q4 expiry.
All same-day-closed findings met their SLA (100% within-SLA on the closed set).

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 8 |
| High | 119 |
| Medium | 128 |
| Low | 7 |
| Info | 9 |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype (test 1) | 103 | 3 | 0 | 2 |
| Trivy Scan (test 2) | 50 | 0 | 0 | 0 |
| Semgrep (test 3) | 22 | 0 | 0 | 0 |
| Checkov (test 5) | 80 | 0 | 0 | 0 |
| KICS ansible (test 6) | 10 | 0 | 0 | 0 |
| KICS pulumi (test 7) | 6 | 0 | 0 | 0 |
| **Total** | **271** | **3** | **0** | **2** |

> The 3 mitigated and 2 risk-accepted findings all originated from the Grype scan (the SCA source
> with the most actionable dependency CVEs), which is why its active count dropped from 108 to 103.

### Program metrics
- **MTTD** (Mean Time to Detect): 0 days — all findings were surfaced by automated scans at import
  time; detection is immediate in a scanner-driven pipeline (the meaningful MTTD signal appears only
  once findings are correlated to introduction dates, which this dataset does not carry).
- **MTTR** (Mean Time to Remediate): ~0 days on the 3 closed findings — detection and remediation
  occurred in the same session (import 2026-07-10, mitigated 2026-07-10). In a real program this
  would span the detect→patch window; the value here demonstrates the metric is computed, not a
  realistic cadence.
- **Vuln-age median** (open findings): 0 days — all 271 open findings were imported today, so age
  has not yet accrued; this becomes meaningful on the next scan cycle.
- **Backlog trend**: +271 findings vs. a zero baseline (first import establishes the baseline; the
  next engagement run measures trend against 271).
- **SLA compliance**: 100% on the closed set (3/3 remediated before their Critical 24h deadline);
  0 findings are currently past-SLA since all open items are within their fresh SLA windows.

### Risk-accepted items (all with expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| GHSA-mp2f-45pm-3cg9 in decompress:4.2.1 (id 105) | Critical | No upstream fix available; low exploitability in this deployment — compensating controls, review Q4 | 2026-10-10 |
| GHSA-5mrr-rgp6-x4gr in marsdb:0.6.11 (id 106) | Critical | Unmaintained package, no patch exists; replacement planned — review Q4 | 2026-10-10 |

> Both risk-acceptances carry an explicit expiry (Lecture 10 slide 12 — the "silent program killer"
> rule): neither is open-ended, and both auto-revert to active on 2026-10-10 for re-evaluation.

### Next-quarter goal (OWASP SAMM ladder step)
Mature the **Defect Management** practice (SAMM Operations domain) from ad-hoc to a metrics-driven
level. Right now MTTR and vuln-age are computed but trivially zero because detection and remediation
collapsed into one session; next quarter the goal is a genuine detect→fix window with a target
High-severity MTTR of ≤7 days (matching the SLA) and a falling backlog trend measured against
today's 271 baseline. Concretely: wire the scanners into CI so findings import continuously with
real introduction dates, and add a Falco-runtime custom parser so runtime alerts (Lab 9) feed the
same DefectDojo backlog — closing the gap between the 6 build/deploy-time tools already integrated
and the runtime layer that currently sits outside the vuln-management program.


## Bonus: Interview Walkthrough
- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: <4:47>
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): "Grype reported it
  as GHSA-xwcq-pm8m-c4vf and Trivy as CVE-2023-46233 — the same bug under two identifiers — so
  cross-tool dedup needs GHSA↔CVE normalization."
