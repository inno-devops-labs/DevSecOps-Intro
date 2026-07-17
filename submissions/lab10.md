# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: **3.1.0** (`defectdojo/defectdojo-django:latest`). Although the lab references v2.58.x, the newer release provides the same API and import workflow required for this assignment.

### Product + Engagement
- Product ID: **1**
- Product name: **OWASP Juice Shop**
- Engagement ID: **2**
- Engagement status: **In Progress**

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 108 |
| 4 | Trivy Scan | trivy.json | 80 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.json | 0 *(JSON format is not supported by the DefectDojo ZAP parser)* |
| 6 | Checkov Scan | results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 100 |
| **Total raw imports** | | | **456** |
| **After dedup** | | | **310 unique findings** |

### Dedup example (Lecture 10 slide 11)

- **CVE/ID:** CVE-2023-46233
- **Number of source tools:** 4 (multiple Trivy scans were merged into a single finding)
- **DefectDojo's single finding ID:** **447**

---

## Task 2: Governance Report

### Executive Summary (3 sentences)

OWASP Juice Shop was analyzed using six different security tools, producing **305 active findings**, including **11 Critical** and **120 High** severity issues after deduplication. During this reporting period, three Critical dependency findings were mitigated, while two Low severity findings were formally accepted as risk with expiration dates. Since all scans were imported during one session, metrics such as MTTR and vulnerability age mainly demonstrate the reporting workflow rather than long-term operational trends.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 11 |
| High | 120 |
| Medium | 156 |
| Low | 9 |

### Findings by source tool

| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 108 | 3 | 0 | 2 |
| Trivy Scan (SBOM) | 80 | 0 | 0 | 0 |
| Semgrep | 22 | 0 | 0 | 0 |
| Checkov | 80 | 0 | 0 | 0 |
| KICS (Ansible) | 10 | 0 | 0 | 0 |
| KICS (Pulumi) | 6 | 0 | 0 | 0 |
| Trivy Scan (image) | 3 | 0 | 0 | 0 |
| Trivy Scan (k8s) | 1 | 0 | 0 | 0 |

### Program metrics

- **MTTD** (Mean Time to Detect): approximately **0 days** (all findings were imported at the same time)
- **MTTR** (Mean Time to Remediate): **0 days**
- **Vuln-age median** (open findings): **0 days**
- **Backlog trend:** baseline established with **310** unique findings
- **SLA compliance:** **100%**

### Risk-accepted items (must have expiry)

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| GHSA-pxg6-pf52-xh8x in cookie 0.4.2 | Low | Low impact and not reachable in the current Juice Shop configuration | 2026-10-10 |
| CVE-2026-48931 in node 24.15.0 | Low | Low-risk base image vulnerability scheduled for the next image update | 2026-10-10 |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)

The next improvement would focus on **Defect Management** by moving from the current workflow to more advanced cross-parser deduplication. At the moment, identical vulnerabilities reported by different scanners may still appear as separate findings. Extending deduplication across tools and integrating Falco runtime alerts into DefectDojo would provide more accurate metrics and simplify vulnerability triage.

---

## Bonus: Interview Walkthrough

- **Walkthrough script:** see `submissions/lab10-walkthrough.md`
- **Practiced runtime:** approximately **4:47**
- **Two anticipated Q&A questions covered:** **Yes**
- **Strongest claim in the script (most-quoted-by-interviewer line, in your view):** *"456 raw findings were reduced to 310 unique findings after deduplication, leaving 11 Critical and 120 High severity issues to prioritize."*
