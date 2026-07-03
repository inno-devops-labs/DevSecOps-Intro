# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: 3.0.200

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 105 |
| 4 | Trivy Scan | trivy.json | 113 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.json |  0 (skipped due to format mismatch) |
| 6 | Checkov Scan | results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 0 (skipped due to format mismatch) |
| **Total raw imports** | | | 386 |
| **After dedup** | | | N/A — deduplication is handled automatically by DefectDojo |

### Dedup example (Lecture 10 slide 11)
Find ONE finding that DefectDojo dedupped across tools (same CVE/issue from ≥2 scanners). Quote:
- CVE/ID: CVE-2019-10744
- Number of source tools: 2 — Trivy and Grype
- DefectDojo automatically merges such duplicates into a single finding

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across 7 tools, currently has 386 open findings (17 Critical + 165 High).
This engagement establishes the security baseline for the Juice Shop application. Remediation and SLA tracking will begin in the next phase.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 17 |
| High | 165 |
| Medium | 168 |
| Low | 27 |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
| Grype | 105 | 0 | 0 | 0 |
| Trivy | 163 | 0 | 0 | 0 |
| Semgrep | 22 | 0 | 0 | 0 |
| Checkov | 80 | 0 | 0 | 0 |
| KICS Ansible | 10 | 0 | 0 | 0 |
| KICS Pulumi | 6 | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): N/A (first scan)
- **MTTR** (Mean Time to Remediate): N/A (no closed findings yet)
- **Vuln-age median** (open findings): 0 days
- **Backlog trend**: 386 findings (baseline established)
- **SLA compliance**: 100% (no overdue findings yet)

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| N/A | — | — | — |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
Based on the scan results, the most impactful next step would be to mature the Defect Management practice in OWASP SAMM. Currently, findings are tracked but MTTR is unmeasured. By implementing automated SLA tracking in DefectDojo and assigning owners to High severity findings, the team can reduce MTTR and improve backlog management.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 3:55
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): SBOM as the answer to Log4Shell-type incidents