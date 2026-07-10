# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: defectdojo/defectdojo-django:latest (defectdojo/defectdojo-nginx:latest)

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 107 |
| 4 | Trivy Scan | trivy.json | (file not found - skipped) |
| 5 | Semgrep JSON Report | semgrep.json | (file not found - skipped) |
| 5 | ZAP Scan | auth-report.json | (file not found - skipped) |
| 6 | Checkov Scan | results_json.json | (file not found - skipped) |
| 6 | KICS Scan | kics-ansible/results.json | (file not found - skipped) |
| 6 | KICS Scan | kics-pulumi/results.json | (file not found - skipped) |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 0 |
| **Total raw imports** | | | 157 |
| **After dedup** | | | 157 unique findings |

### Dedup example (Lecture 10 slide 11)
Find ONE finding that DefectDojo dedupped across tools (same CVE/issue from ≥2 scanners).  
- CVE/ID: (обнаружить через UI, но данные показали, что все 157 находок уникальны для этого набора импортов)
- Number of source tools: (не удалось определить из API, но можно предположить, что Grype и Trivy частично перекрываются)
- DefectDojo's single finding ID: (требуется просмотр в UI)

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across 2 tools (Grype, Trivy image), currently has 25 open findings (4 Critical + 13 High + 8 Medium). Mean Time to Remediate (MTTR) not yet calculated (findings not closed). 0% of findings closed within their SLA (none closed yet).

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 4 |
| High | 13 |
| Medium | 8 |
| Low | 0 |
| Info | 0 |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 107 | 0 | 0 | 0 |
| Trivy Scan | 50 | 0 | 0 | 0 |
| Trivy Operator Scan | 0 | 0 | 0 | 0 |
| (others) | 0 | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): Not applicable (findings imported from existing scans)
- **MTTR** (Mean Time to Remediate): 0 days (no findings closed yet)
- **Vuln-age median** (open findings): Not calculated (no detection dates)
- **Backlog trend**: 157 findings imported (baseline)
- **SLA compliance**: 0% (no findings closed)

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| (none risk-accepted yet) | | | |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
I would mature the **Defect Management** practice — specifically, automate remediation workflows. Currently, MTTR is 0 days because no findings have been closed; we need to establish a process for developers to fix and close findings. Target: reduce High findings by 50% next quarter and start measuring MTTR against the SLA matrix (Critical: 24h, High: 7d, Medium: 30d, Low: 90d). This aligns with SAMM's "Defect Management" practice at level 2 (basic metrics + SLA).

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: not practiced yet
- Two anticipated Q&A questions covered: no
- Strongest claim in the script: not applicable
