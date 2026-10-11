# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: DefectDojo v2.58.2 (`defectdojo/defectdojo-django:latest`)

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 4
- Engagement status: In Progress

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 104 |
| 4 | Trivy Scan | trivy.json | 112 |
| 5 | Semgrep JSON Report | semgrep.json | 27 |
| 5 | ZAP Scan | auth-report.json | 12 |
| 6 | Checkov Scan | results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 0 |
| **Total raw imports** | | | **401** |
| **After dedup** | | | **400 unique findings** |

### Dedup example (Lecture 10 slide 11)

Find ONE finding that DefectDojo dedupped across tools (same CVE/issue from ≥2 scanners). Quote:

- CVE/ID: CVE-2021-23337
- Number of source tools: 2 — Trivy Scan, Trivy Scan (image)
- DefectDojo's single finding ID: 163

## Task 2: Governance Report

### Executive Summary (3 sentences)

Juice Shop, scanned across 9 imported scan sources (7 tools), currently has 400 open findings (17 Critical + 165 High). Mean Time to Remediate (MTTR) on closed-this-period findings is not available because no findings have been mitigated yet. 100% of findings are currently within their configured SLA.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 17 |
| High | 165 |
| Medium | 176 |
| Low | 29 |
| Info | 13 |

### Findings by source tool

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
- **MTTR** (Mean Time to Remediate): N/A
- **Vuln-age median** (open findings): 0 days
- **Backlog trend**: +400 findings vs. baseline
- **SLA compliance**: 100%

### Risk-accepted items (must have expiry)

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| CVE-2026-42766 (Libssl3t64 package) | Low | Accepted for the course demonstration environment; remediation deferred because it does not affect the lab objectives | 2027-01-04 |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)

The next SAMM practice to mature would be **Defect Management**. The current backlog includes 165 High-severity findings with no remediation history yet, so the primary goal is to establish an SLA-driven remediation workflow and reduce MTTR for High findings below 7 days through regular DefectDojo imports and vulnerability triage.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4:30
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): "Multiple security scanners become significantly more valuable when their findings are centralized, deduplicated, and managed through a single governance process."
