# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: dev

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json |                 0 |
| 4 | Trivy Scan | trivy.json |                50 |
| 5 | Semgrep JSON Report | semgrep.json |                22 |
| 5 | ZAP Scan | auth-report.json |                 0 |
| 6 | Checkov Scan | results_json.json |                80 |
| 6 | KICS Scan | kics-ansible/results.json |                10 |
| 6 | KICS Scan | kics-pulumi/results.json | 0 |
| 7 | Trivy Scan (image) | trivy-image.json |               106 |
| 7 | Trivy Operator Scan | trivy-k8s.json |                 0 |
| **Total raw imports** | | |               268 |
| **After dedup** | | |               267 |

### Dedup example (Lecture 10 slide 11)
Find ONE finding that DefectDojo dedupped across tools (same CVE/issue from ≥2 scanners). Quote:
- CVE/ID: CVE-2015-9235 (Jsonwebtoken 0.4.0)
- Number of source tools: 2 (both from Trivy Scan — same scanner, duplicate within the same test type)
- DefectDojo's single finding ID: Original — 763 (Critical), Duplicate — ID not shown

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across 8 tools, currently has 266 open findings (10 Critical + 108 High).
Mean Time to Remediate (MTTR) on closed-this-period findings is 1 day. 100% of findings closed
within their SLA.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical |    10 |
| High |   108 |
| Medium |   127 |
| Low |    21 |

### Findings by source tool
| Tool | Active | Mitigated |   False Positive | Risk Accepted |
|------|-------:|----------:|-----------------:|--------------:|
|Anchore Grype|      0 |         0 |                0 |             0 |
|Checkov Scan|     80 |         0 |                0 |             0 |
|Generic Findings Import|      0 |         0 |                0 |             0 |
|KICS Scan|     10 |         0 |                0 |             0 |
|Semgrep JSON Report|     22 |         0 |                0 |             0 |
|Trivy Operator Scan|      0 |         0 |                0 |             0 |
|Trivy Scan|     49 |         0 |                0 |             0 |
|Trivy Scan|    106 |         2 |                0 |             0 |

### Program metrics
- **MTTD** (Mean Time to Detect): 0 days
- **MTTR** (Mean Time to Remediate): 1 day
- **Vuln-age median** (open findings): 0 days
- **Backlog trend**: +0 findings vs. baseline
- **SLA compliance**: 100%

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| CVE-2026-45446 Libssl3t64 3.5.5-1~deb13u2 | Low | Low impact, acceptable risk | 29.07.2026  |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
What ONE concrete SAMM practice would you mature next quarter, and why?
(2-3 sentences with specific data — e.g., "Defect Management — current MTTR for High
is X days, target Y; add Falco-runtime ingestion via custom parser.")

 I would mature Defect Management from Initial to Defined by enforcing SLA-based remediation workflows in DefectDojo and integrating with Jira to automate ticket assignment and escalation. This would reduce MTTR for High findings from 1 day to ≤7 days and ensure all Critical findings are addressed within 1 day, based on the current SLA matrix (Critical: 1 day, High: 7 days).
