# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: `defectdojo/defectdojo-django:latest`, image ID `34007144bc71`, upstream checkout `3.1.0` (`5ddac02bf4`)

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 109 |
| 4 | Trivy Scan | trivy.json | 114 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.json | 11 |
| 6 | Checkov Scan | results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 51 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 0 |
| **Total raw imports** | | | 403 |
| **After dedup** | | | 351 unique findings |

Falco runtime logs were not imported because this DefectDojo instance has no stock parser for the custom `falco.log` format.
ZAP `auth-report.json` was retained as the lab output; DefectDojo imported the equivalent `auth-report.xml` because the stock `ZAP Scan` parser rejected JSON.

### Dedup example (Lecture 10 slide 11)
Find ONE finding that DefectDojo dedupped across tools (same CVE/issue from ≥2 scanners). Quote:
- CVE/ID: GHSA-5mrr-rgp6-x4gr in `marsdb` 0.6.11
- Number of source tools: 3 - Anchore Grype, Trivy Scan, Trivy image scan
- DefectDojo's single finding ID: 107 (`170` and `360` are duplicate-linked to `107`)

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across 8 imported scan sources, currently has 350 open findings (13 Critical + 121 High).
Mean Time to Remediate (MTTR) on closed-this-period findings is N/A because 0 findings were mitigated in this capstone run.
96.6% of currently open findings are within their configured SLA.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 13 |
| High | 121 |
| Medium | 173 |
| Low | 31 |
| Info | 12 |
| **Total** | 350 |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 108 | 0 | 0 | 1 |
| Trivy Scan | 113 | 0 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 |
| Checkov Scan | 80 | 0 | 0 | 0 |
| KICS Scan (Ansible) | 10 | 0 | 0 | 0 |
| KICS Scan (Pulumi) | 6 | 0 | 0 | 0 |
| Trivy Scan (image) | 0 | 0 | 0 | 0 |
| ZAP Scan | 11 | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): 0 days
- **MTTR** (Mean Time to Remediate): N/A (0 mitigated findings)
- **Vuln-age median** (open findings): 0 days
- **Backlog trend**: +350 findings vs. baseline 0
- **SLA compliance**: 96.6%

SLA matrix applied in DefectDojo as `Lab10 SLA Matrix`: Critical 1 day, High 7 days, Medium 30 days, Low 90 days.

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| GHSA-pxg6-pf52-xh8x in `cookie` 0.4.2 | Low | Low-severity transitive dependency accepted for the capstone period; revisit during dependency upgrade batch. | 2026-10-06 |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
Mature OWASP SAMM Defect Management from Initial to Defined.
The current backlog has 350 active findings and no mitigated findings, so the next quarter should add owner assignment, ticket creation, and weekly SLA review for Critical and High findings.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4 minutes:42 seconds
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): "The program changed the problem from scanner output to governed risk."
