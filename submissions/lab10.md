# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: 3.1.0

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 104 |
| 4 | Trivy Scan | trivy.json | 105 |
| 5 | Semgrep JSON Report | semgrep.json | 0 |
| 5 | ZAP Scan | auth-report.json | Failed, different format needed |
| 6 | Checkov Scan | results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 42 |
| 7 | Trivy Operator Scan | trivy-k8s.json | No such file due to skipped optional task 2 of lab 7 |
| **Total raw imports** | | | 347 |
| **After dedup** | | | 347 |
Deduplication is not enabled, therefore i have no way other than manual to get the "after dedup" number.

### Dedup example (Lecture 10 slide 11)
Find ONE finding that DefectDojo dedupped across tools (same CVE/issue from ≥2 scanners). Quote:
- CVE/ID: GHSA-c7hr-j4mj-j2w6
- Number of source tools: 1, Grype, but 2 different findings(different versions)
- DefectDojo's single finding ID: 2

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across 6 tools, currently has 347 open findings (17 Critical + 136 High).
Mean Time to Remediate (MTTR) on closed-this-period findings is 0 days. <n>% of findings closed
within their SLA.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 17 |
| High | 136 |
| Medium | 158 |
| Low | 27 |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 104 | 0 | 0 | 0 |
| Trivy Scan (Lab 4) | 105 | 0 | 0 | 0 |
| Semgrep | 0 | 0 | 0 | 0 |
| ZAP Scan | 0 | 0 | 0 | 0 |
| Checkov | 80 | 0 | 0 | 0 |
| KICS (Ansible) | 10 | 0 | 0 | 0 |
| KICS (Pulumi) | 6 | 0 | 0 | 0 |
| Trivy Scan (Lab 7) | 42 | 0 | 0 | 0 |
| **Total** | **347** | **0** | **0** | **0** |

### Program metrics
- **MTTD** (Mean Time to Detect): n/a - no data available
- **MTTR** (Mean Time to Remediate): n/a - no mitigated findings
- **Vuln-age median** (open findings): n/a - no data available
- **Backlog trend**: 347 findings, baseline not yet established
- **SLA compliance**: n/a - no mitigated yet

### Risk-accepted items (must have expiry)
No findings are currently "risk accepted"

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
What ONE concrete SAMM practice would you mature next quarter, and why?
(2-3 sentences with specific data — e.g., "Defect Management — current MTTR for High
is X days, target Y; add Falco-runtime ingestion via custom parser.")

Defect Management. Since now there are 347 vulnerabilities and 17 are critical, none yet fixed. Next quarter a process must be created to fix them with compliance to SLA.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 8:50
- Two anticipated Q&A questions covered: yes 
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): 347 findinfs were idenified with 6 tools.