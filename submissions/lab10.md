# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: `defectdojo/defectdojo-django:latest` (v3.1.0)

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 4
- Engagement name: Final Submission Run
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 104 |
| 4 | Trivy Scan | trivy.json | 112 |
| 5 | Semgrep JSON Report | semgrep.json | 27 |
| 5 | ZAP Scan | auth-report.xml | 12 |
| 6 | Checkov Scan | results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 0 |
| **Total raw imports** | | | **401** |
| **After dedup** | | | **401** |

### Dedup example (Lecture 10 slide 11)
Trivy Operator Scan (`trivy-k8s.json`) imported **0** new findings into engagement 4 because the same CVEs were already present from Grype/Trivy image imports (`deduplication_on_engagement=true`). Quote:
- CVE/ID: CVE-2026-34181 (and related OpenSSL CVEs already in engagement from Trivy Scan imports)
- Number of source tools: 2 — Trivy Scan (image), Trivy Operator Scan (k8s manifest)
- DefectDojo result: second import added 0 duplicate rows (see `import-results-trivy-k8s.json` → `statistics.after.total.total = 0`)

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across 9 tools in engagement **Final Submission Run** (id 4), currently has 400 active findings (17 Critical + 165 High) after one Low-severity item was risk-accepted.
Mean Time to Remediate (MTTR) on closed-this-period findings is N/A (no findings closed yet). 100% of open findings in this engagement are within their SLA window: the **DevSecOps** SLA profile (Critical 1d / High 7d / Medium 30d / Low 90d) is applied at the **Product** level on OWASP Juice Shop (id 1) and inherited by all engagements under that product.

### Findings by severity (active only, engagement 4)
| Severity | Count |
|----------|------:|
| Critical | 17 |
| High | 165 |
| Medium | 176 |
| Low | 29 |
| Info | 13 |

### Findings by source tool (engagement 4)
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 104 | 0 | 0 | 0 |
| Trivy Scan | 161 | 0 | 0 | 1 |
| Semgrep JSON Report | 27 | 0 | 0 | 0 |
| ZAP Scan | 12 | 0 | 0 | 0 |
| Checkov Scan | 80 | 0 | 0 | 0 |
| KICS Scan | 16 | 0 | 0 | 0 |
| Trivy Operator Scan | 0 | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): 0 days
- **MTTR** (Mean Time to Remediate): N/A days
- **Vuln-age median** (open findings): 0 days
- **Backlog trend**: +400 active findings vs. baseline 0 (401 total imported, 1 risk-accepted)
- **SLA compliance**: 100%
- **SLA configuration**: DevSecOps (id 3) on Product 1

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| CVE-2026-42766 Libssl3t64 3.5.5-1~deb13u2 (Trivy Scan, engagement 4, status: Inactive, Verified, Risk Accepted) | Low | Demo Juice Shop, accepted for course capstone only | 2027-01-04 |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
In the next quarter I will mature the Defect Management SAMM practice. The baseline shows 165 open High findings with no remediation MTTR yet. The concrete goal is to drive High-finding MTTR under 7 days by prioritizing fix-available CVEs from Grype/Trivy imports and wiring DefectDojo imports into a single clean engagement per release.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: `~4:34`
- Two anticipated Q&A questions covered: `yes`
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): *"Nine scanners, one engagement, one SLA matrix: DefectDojo turns scan noise into a program leaders can measure."*
