# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: defectdojo/defectdojo-django:latest
- Admin password: admin (default from dev environment)

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 0 |
| 6 | Checkov Scan | results_json.json | 80 |
| 6 | KICS Scan | results.json | 6 |
| 4 | Anchore Grype | grype-from-sbom.json | 48 |
| **Total raw imports** | | | 206 |
| **After dedup** | | | 158 |

### Dedup example (Lecture 10 slide 11)
Find ONE finding that DefectDojo dedupped across tools (same CVE/issue from ≥2 scanners). Quote:
- CVE/ID: CVE-2024-21626 (runc Leaky Vessels vulnerability)
- Number of source tools: 2 — Trivy Scan, Anchore Grype
- DefectDojo's single finding ID: 104

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across 4 tools, currently has 158 open findings (5 Critical + 45 High).
Mean Time to Remediate (MTTR) on closed-this-period findings is 0 days. 0% of findings closed
within their SLA.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 47 |
| Medium | 104 |
| Low | 0 |
| Info | 2 |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Trivy | 50 | 0 | 0 | 0 |
| Semgrep | 22 | 0 | 0 | 0 |
| Checkov | 80 | 0 | 0 | 0 |
| KICS | 6 | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): 0 days
- **MTTR** (Mean Time to Remediate): N/A (no findings closed yet)
- **Vuln-age median** (open findings): 0 days (just imported)
- **Backlog trend**: +158 findings vs. baseline
- **SLA compliance**: 100% (all within SLA since they were just created)

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| CVE-2024-21626 | Critical | Waiting on upstream fix from vendor; container runs unprivileged | 2026-07-30 |

### Next-quarter goal (OWASP SAMM ladder step)
Our next-quarter goal is to advance "Defect Management" to SAMM Maturity Level 2. Currently, MTTR is undefined because we just onboarded DefectDojo. We will implement automated JIRA ticketing for Critical/High findings to establish an MTTR baseline and reduce it below our 7-day SLA target.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4:30
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): "By shifting left with pre-commit hooks and Checkov, while simultaneously establishing a runtime eBPF net with Falco, we caught misconfigurations before they shipped and maintained full visibility into the cluster."
