# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: v. 3.1.0

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 120 |
| 4 | Trivy Scan | trivy.json | 80 |
| 5 | Semgrep JSON Report | semgrep.json | 40 |
| 5 | ZAP Scan | auth-report.json | 30 |
| 6 | Checkov Scan | results_json.json | 20 |
| 6 | KICS Scan | kics-ansible/results.json | 15 |
| 6 | KICS Scan | kics-pulumi/results.json | 10 |
| 7 | Trivy Scan (image) | trivy-image.json | 100 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 60 |
| **Total raw imports** | | | 475 |
| **After dedup** | | | 385 |

### Dedup example (Lecture 10 slide 11)
Find ONE finding that DefectDojo dedupped across tools (same CVE/issue from ≥2 scanners). Quote:
- CVE/ID: CVE-2024-21626
- Number of source tools: 2 — Trivy image, Grype
- DefectDojo's single finding ID: 1

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across 9 tool runs, currently has 385 open findings (17 Critical + 164 High).
Mean Time to Remediate (MTTR) is N/A as no findings have been closed yet in this period.
0% of findings closed within their SLA.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 17 |
| High | 164 |
| Medium | 168 |
| Low | 27 |
| Info | 9 |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 120 | 0 | 0 | 0 |
| Trivy | 180 | 0 | 0 | 0 |
| Semgrep | 40 | 0 | 0 | 0 |
| ZAP | 30 | 0 | 0 | 0 |
| Checkov | 20 | 0 | 0 | 0 |
| KICS | 25 | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): 0 days
- **MTTR** (Mean Time to Remediate): N/A
- **Vuln-age median** (open findings): 0 days
- **Backlog trend**: +385 findings vs. 0 baseline
- **SLA compliance**: 0%

### Risk-accepted items (must have expiry)
None currently risk-accepted.

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
I would mature the "Defect Management" practice by implementing an automated feedback loop between DefectDojo and the development team's Jira board. This will reduce the current MTTR by streamlining the triage-to-remediation pipeline.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4:45
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "I would immediately query the aggregated SBOMs in DefectDojo to identify every service using the affected library version."
