# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: **2.58.4**
- Deployment: official Docker Compose
- UI: http://localhost:8080

### Product + Engagement
- Product ID: **1**
- Product name: OWASP Juice Shop
- Engagement ID: **1**
- Engagement status: In Progress

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 104 |
| 4 | Trivy Scan | trivy.json | 113 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.json | 12 |
| 6 | Checkov Scan | results_json.json | 59 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 48 |
| **Total raw imports** | | | **424** |
| **After dedup** | | | **316 unique findings** |

### Dedup example (Lecture 10 slide 11)

DefectDojo successfully merged duplicate findings reported by multiple scanners.

- CVE/ID: **CVE-2024-21626**
- Number of source tools: **3** (Grype, Trivy Image, Trivy Operator)
- DefectDojo's single finding ID: **483**

Duplicate findings were linked to the same canonical finding instead of being counted multiple times.

## Task 2: Governance Report

### SLA matrix applied

| Severity | SLA |
|----------|-----|
| Critical | 1 day |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

### Executive Summary

Security findings from SCA, SAST, DAST, IaC and container scans were imported into DefectDojo and centralized in a single engagement. After enabling deduplication, repeated findings detected by multiple scanners were merged into single canonical findings, reducing analyst workload. At the time of submission all findings remain within the configured SLA windows.

### Findings by severity

| Severity | Count |
|----------|------:|
| Critical | 12 |
| High | 121 |
| Medium | 147 |
| Low | 27 |
| Info | 9 |

### Findings by source tool

| Tool | Active |
|------|-------:|
| Anchore Grype | 104 |
| Trivy Scan | 113 |
| Semgrep | 22 |
| ZAP | 12 |
| Checkov | 59 |
| KICS (Ansible) | 10 |
| KICS (Pulumi) | 6 |
| Trivy Image | 2 |
| Trivy Operator | 0 |

### Program metrics

- **MTTD:** ≈ 0 days
- **MTTR:** ≈ 0 days
- **Median vulnerability age:** ≈ 0 days
- **Backlog:** 316 unique findings
- **SLA compliance:** 100%

### Risk-accepted items

| Finding | Severity | Reason | Expiry |
|---------|----------|--------|--------|
| CVE-2024-21626 | High | Planned upgrade during the next maintenance cycle | 2026-10-10 |

### Next-quarter goal

Automate imports through CI/CD and integrate runtime security events (Falco) into DefectDojo so that runtime findings become part of the same vulnerability management process.