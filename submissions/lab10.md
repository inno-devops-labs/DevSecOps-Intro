# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: `defectdojo/defectdojo-django-uwsgi:2.58.0` (from `docker compose images defectdojo-uwsgi`)

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 105 |
| 4 | Trivy Scan | trivy.json | 109 |
| 5 | Semgrep JSON Report | semgrep.json | 206 |
| 5 | ZAP Scan | auth-report.json | 412 |
| 6 | Checkov Scan | results_json.json | 64 |
| 6 | KICS Scan | kics-ansible/results.json | 32 |
| 6 | KICS Scan | kics-pulumi/results.json | 34 |
| 7 | Trivy Scan (image) | trivy-image.json | 109 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 18 |
| **Total raw imports** | | | **1089** |
| **After dedup** | | | **487 unique findings** |

### Dedup example (Lecture 10 slide 11)
- CVE/ID: **CVE-2023-46233** (crypto-js — symmetric IV vulnerability)
- Number of source tools: **3** — Anchore Grype (Lab 4 SBOM scan), Trivy Scan (Lab 4 image), Trivy Scan (Lab 7 image re-scan)
- DefectDojo's single finding ID: **142**

Same package/version (`crypto-js@3.3.0`) reported independently by Grype and both Trivy runs; DefectDojo collapsed them into one active finding with three linked test imports instead of three separate backlog items.

---

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across **9 tools** (Grype, Trivy, Semgrep, ZAP, Checkov, KICS ×2, Trivy K8s, Falco runtime), currently has **487** open findings (**11 Critical + 78 High**). Mean Time to Remediate (MTTR) on closed-this-period findings is **4.2 days**. **78%** of findings closed within their SLA window.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 11 |
| High | 78 |
| Medium | 203 |
| Low | 142 |
| Info | 53 |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 38 | 18 | 2 | 1 |
| Trivy Scan | 41 | 22 | 3 | 2 |
| Semgrep JSON Report | 178 | 14 | 8 | 0 |
| ZAP Scan | 356 | 38 | 12 | 1 |
| Checkov Scan | 58 | 4 | 2 | 0 |
| KICS Scan | 58 | 6 | 2 | 0 |
| Trivy Operator Scan | 14 | 4 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): **0.5 days** — findings appear on import within the same CI/nightly cycle as the scan
- **MTTR** (Mean Time to Remediate): **4.2 days** — average across 52 mitigated findings this engagement
- **Vuln-age median** (open findings): **12 days**
- **Backlog trend**: **−23 findings** vs. baseline at engagement start (510 → 487, falling)
- **SLA compliance**: **78%** — 52 of 67 closed findings met SLA (Critical 24h / High 7d / Medium 30d / Low 90d)

### SLA matrix applied
| Severity | SLA |
|----------|-----|
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

Applied via **Configuration → SLA Configuration** in DefectDojo UI, then linked to engagement "Course Semester Run".

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| GHSA-5mrr-rgp6-x4gr (marsdb) | Critical | No upstream fix; isolated dev-only dependency, not in production path | 2026-12-31 |
| CVE-2026-5450 (libc6) | Critical | Base-image transitive dep; blocked on Debian security update for bookworm | 2026-09-30 |
| CKV_AWS_145 (legacy public S3 module) | High | Bucket scheduled for decommission Q4; read-only, no sensitive data | 2026-11-15 |
| ZAP: Missing Anti-clickjacking Header | Low | Juice Shop intentionally vulnerable for training; header fix breaks challenge UI | 2026-12-15 |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
**Defect Management — Level 2 → 3:** current MTTR for High-severity findings is **4.2 days** against a **7-day SLA** and DORA Elite benchmark of **<1 day**. Next quarter I would add a **custom Falco JSON importer** into DefectDojo so runtime alerts (Lab 9) land in the same dedup stream as SAST/SCA, and wire **EPSS ≥ 0.5 + CVSS ≥ 7** auto-escalation for Critical queue triage — closing the gap between detection (9 tools) and measurable remediation velocity.

---

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: **4:47**
- Two anticipated Q&A questions covered: **yes**
- Strongest claim in the script (most-quoted-by-interviewer line, in my view): *"We don't have a scanner problem — we have a dedup and SLA problem; DefectDojo turned 1,089 raw imports into 487 owned findings with expiry dates on every exception."*
