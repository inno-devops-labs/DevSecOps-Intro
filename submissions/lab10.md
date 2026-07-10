## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: `defectdojo/defectdojo-django:latest`

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 92 |
| 4 | Trivy Scan | trivy.json | 93 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.json | 12 |
| 6 | Checkov Scan | results_json.json | 78 |
| 6 | KICS Scan | results.json | 16 |
| 7 | Trivy Scan (image) | trivy-image.json | 48 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 3 |
| **Total raw imports** | | | 364 |
| **After dedup** | | | 152 | 

### Dedup example (Lecture 10 slide 11)
Find ONE finding that DefectDojo dedupped across tools (same CVE/issue from ≥2 scanners). Quote:
- CVE/ID: CVE-2026-45447
- Number of source tools: 3 — Trivy image, Trivy, Grype
- DefectDojo's single finding ID: 416


## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned across 8 tools, currently has 152 open findings (5 Critical + 48 High).
Mean Time to Remediate (MTTR) on closed-this-period findings is - days. -% of findings closed
within their SLA.

`Note: MTTR & SLA compliance are not yet measurable: this engagement
establishes the baseline for future quarters.`

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 48 |
| Medium | 62 |
| Low | 37 |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Trivy Scan (image) | 48 | 0 | 0 | 0 |
| Trivy Scan (Lab 4) | 93 | 0 | 0 | 0 |
| Anchore Grype | 92 | 0 | 0 | 0 |
| Checkov Scan | 78 | 0 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 |
| KICS Scan | 16 | 0 | 0 | 0 |
| ZAP Scan | 12 | 0 | 0 | 0 |
| Trivy Operator Scan | 3 | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): 1 day
- **MTTR** (Mean Time to Remediate): N/A — no findings have been mitigated yet in this engagement
- **Vuln-age median** (open findings): 21 days
- **Backlog trend**: +152 findings vs. first engagement 
- **SLA compliance**: N/A — SLA matrix applied but no findings have been triaged/closed yet to measure compliance

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| CVE-2015-9235 (jsonwebtoken) | critical | Affected endpoint not exposed in production config | 2026-12-15 |
| CVE-2019-10744 (lodash) | critical | Prototype pollution — not exploitable in current Node.js version | 2026-12-15 |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
What ONE concrete SAMM practice would you mature next quarter, and why?
(2-3 sentences with specific data — e.g., "Defect Management — current MTTR for High
is X days, target Y; add Falco-runtime ingestion via custom parser.")

In the coming quarter: implement a Kyverno-based admission control mechanism to block critical IaC configuration errors prior to deployment, rather than detecting them after the fact. This will enable a shift from simple scanning to automated compliance enforcement and reduce the mean time to remediation (MTTR) by catching issues at the pre-deployment stage.

