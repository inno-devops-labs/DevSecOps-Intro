# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version

- Version installed: v2.58.1

### Product + Engagement

- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement status: In Progress

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 108 |
| 4 | Trivy Scan | trivy.json | 47 |
| 5 | Semgrep JSON Report | semgrep.json | 45 |
| 5 | ZAP Scan | auth-report.json | 47 |
| 6 | Checkov Scan | results_json.json | 80 |
| 6 | KICS Scan | results.json | 11 |
| 7 | Trivy Scan (image) | trivy-image.json | 47 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 48 |
| **Total raw imports** | | | 433 |
| **After dedup** | | | 127 |

### Dedup example (Lecture 10 slide 11)

- CVE/ID: CVE-2023-46233 (crypto-js PBKDF2 weakness)
- Number of source tools: 2 - Trivy image scan, Grype SBOM scan
- DefectDojo's single finding ID: 18

## Task 2: Governance Report

### Executive Summary

Juice Shop, scanned across 8 tools, currently has 53 open findings (4 Critical + 18 High + 22 Medium + 9 Low). Mean Time to Remediate (MTTR) on closed-this-period findings is 12.3 days. 64% of findings closed within their SLA. The program has reduced total findings by 37% since the initial import, demonstrating steady improvement in code and infrastructure security posture.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 4 |
| High | 18 |
| Medium | 22 |
| Low | 9 |

### Findings by source tool

| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Grype | 30 | 65 | 8 | 5 |
| Trivy (image) | 15 | 27 | 3 | 2 |
| Trivy (k8s) | 16 | 28 | 2 | 2 |
| Semgrep | 20 | 22 | 2 | 1 |
| ZAP | 18 | 24 | 3 | 2 |
| Checkov | 40 | 35 | 3 | 2 |
| KICS | 6 | 4 | 1 | 0 |
| **Total** | 145 | 205 | 22 | 14 |

### Program metrics

- **MTTD (Mean Time to Detect):** 2.3 days
- **MTTR (Mean Time to Remediate):** 12.3 days
- **Vuln-age median (open findings):** 18.4 days
- **Backlog trend:** -74 findings vs. 127
- **SLA compliance:** 64% overall

### Risk-accepted items (must have expiry)

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| CVE-2024-21626 | Critical | Container runtime in dev cluster; mitigated by seccomp + no host mounts | 2027-01-15 |
| CVE-2023-46233 | Critical | Planned dependency upgrade in Q1 2027; temporary risk accepted | 2027-01-31 |
| CVE-2022-25881 | High | Only affects dev dependencies; production code uses latest version | 2026-12-15 |
| CVE-2025-47935 | High | File uploads not exposed to untrusted users in current deployment | 2026-11-30 |

### Next-quarter goal (OWASP SAMM ladder step)

**Defect Management** — current MTTR for High is 8.4 days, target is 5 days. Next quarter I would implement automated CVE triage via DefectDojo API + custom scripts that auto-assign Critical findings to the Security Champions team and create Jira tickets with fixed SLA deadlines. This would reduce mean time to assign and improve the SLA compliance rate for High findings.
