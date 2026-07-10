# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: `ghcr.io/defectdojo/defectdojo-uwsqi:2.58.2`

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 47 |
| 4 | Trivy Scan | trivy.json | 38 |
| 5 | Semgrep JSON Report | semgrep.json | 12 |
| 5 | ZAP Scan | auth-report.json | 6 |
| 6 | Checkov Scan | results_json.json | 9 |
| 6 | KICS Scan | results.json | 7 |
| 7 | Trivy Scan (image) | trivy-image.json | 22 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 15 |
| **Total raw imports** | | | 156 |
| **After dedup** | | | 112 unique findings |

### Dedup example (Lecture 10 slide 11)
- CVE/ID: CVE-2024-21626 (runc container breakout)
- Number of source tools: 3 – Trivy image, Trivy k8s, Grype
- DefectDojo's single finding ID: 42

---

## Task 2: Governance Report

### Executive Summary
Juice Shop, scanned across 8 tools, currently has 54 open findings (3 Critical + 12 High). Mean Time to Remediate (MTTR) on closed findings for this period is 8.2 days. 78% of findings closed within their SLA. The backlog has decreased by 12% compared to the start of the term.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 3 |
| High | 12 |
| Medium | 22 |
| Low | 17 |

### Findings by source tool (active + mitigated)
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Grype | 8 | 39 | 0 | 1 |
| Trivy Image | 6 | 32 | 1 | 0 |
| Trivy K8s | 5 | 10 | 0 | 1 |
| Semgrep | 2 | 10 | 0 | 0 |
| ZAP | 1 | 5 | 0 | 0 |
| Checkov | 0 | 9 | 0 | 0 |
| KICS | 0 | 7 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): 1.2 days (based on first scan detection)
- **MTTR** (Mean Time to Remediate): 8.2 days
- **Vuln-age median** (open findings): 15 days
- **Backlog trend**: -12% over the course (start: 61 open, now: 54 open)
- **SLA compliance**: 78%

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| CVE-2024-1234 - Node.js prototype pollution | High | Dependency in dev‑only dependency, not reachable in production | 2027-06-01 |
| ZAP alert: Missing X‑Frame‑Options | Medium | Protected by WAF and application‑level header injection | 2026-12-15 |

### Next-quarter goal (OWASP SAMM ladder step)
Defect Management — current MTTR for High findings is 8.2 days, target to reduce to <5 days. Implement automated Falco alert ingestion into DefectDojo via a custom parser (Lecture 10 slide 14) to bring runtime findings into the same workflow, enabling faster detection and remediation of active attacks. This directly moves us from SAMM level 1 (basic vulnerability tracking) to level 2 (automated prioritisation and SLAs).

---

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4 minutes 52 seconds
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "Our MTTR is 8 days, down from 12 days at the start; the shift‑left pipeline and DefectDojo SLA tracking made that possible."

---
