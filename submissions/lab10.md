# Lab 10 — Vulnerability Management with DefectDojo

## Task 1: DefectDojo Setup + Import

### DefectDojo version

- Version installed: DefectDojo 2.58.4
- Deployment mode: local Docker Compose release configuration
- URL: http://localhost:8080
- Runtime evidence:
  - `curl -I http://localhost:8080` returned `HTTP/1.1 302 Found`
  - Redirect target: `/login?next=/`

### Product + Engagement

- Product Type ID: 2
- Product Type name: Course Labs
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement name: Course Semester Run
- Engagement status: In Progress

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | `labs/lab4/grype-from-sbom.json` | 104 |
| 4 | Trivy Scan | `labs/lab4/trivy.json` | 113 |
| 5 | Semgrep JSON Report | `labs/lab5/results/semgrep.json` | 22 |
| 5 | ZAP Scan | `labs/lab5/results/auth-report.json` | 0 |
| 6 | Checkov Scan | `labs/lab6/results/checkov-terraform/results_json.json` | 80 |
| 6 | KICS Scan | `labs/lab6/results/kics-ansible/results.json` | 10 |
| 6 | KICS Scan | `labs/lab6/results/kics-pulumi/results.json` | 6 |
| 7 | Trivy Scan | `labs/lab7/results/trivy-image.json` | 50 |
| 7 | Trivy Operator Scan | `labs/lab7/results/trivy-k8s.json` | 0 |
| 9 | Falco custom runtime alerts | `labs/lab9/falco/logs/falco.log` | Not imported: custom runtime log format is not supported by the default importer |
| **Total raw imported findings** | | | **385** |
| **After DefectDojo import/dedup processing** | | | **385** |

### Import notes

The ZAP authenticated report existed as JSON, but DefectDojo's `ZAP Scan` parser in this local run expected XML and returned:

    Wrong file format, please use xml.

The Trivy Operator Scan test was created, but the imported report produced 0 findings in DefectDojo. This was documented as an importer/format limitation for this local run.

### Dedup / cross-tool correlation example

A repeated advisory was identified across scanner outputs:

- Advisory ID: `GHSA-5mrr-rgp6-x4gr`
- Affected package: `marsdb:0.6.11`
- Severity: Critical
- Related DefectDojo findings:
  - Finding ID 98 — `GHSA-5mrr-rgp6-x4gr in marsdb:0.6.11` — Test 1 — Anchore Grype
  - Finding ID 164 — `GHSA-5mrr-rgp6-x4gr Marsdb 0.6.11` — Test 2 — Trivy Scan
  - Finding ID 353 — `GHSA-5mrr-rgp6-x4gr Marsdb 0.6.11` — Test 8 — Trivy Scan
- Number of source tools/tests: 3
- Observed dedup status:
  - `duplicate: false`
  - `duplicate_finding: null`

In this local run, DefectDojo successfully centralized the scanner outputs, but automatic cross-tool deduplication did not collapse this repeated GHSA advisory into a single finding. The likely reason is scanner-specific metadata differences: Grype and Trivy produced slightly different titles, and the `cve` field was not populated for these imported SCA records. This is an important governance finding: before relying on cross-tool deduplication in CI/CD, scanner metadata should be normalized and DefectDojo deduplication rules should be validated.

---

## Task 2: Governance Report

### SLA matrix

The SLA matrix from Lecture 9 / Lecture 10 was applied as the target vulnerability management policy:

| Severity | SLA |
|----------|-----|
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

### Executive Summary

OWASP Juice Shop was scanned across multiple DevSecOps layers: SBOM/SCA, SAST, DAST, IaC, container image scanning, Kubernetes scanning, supply-chain verification, and runtime monitoring. DefectDojo centralized 385 findings from the successful imports, including 17 Critical and 164 High active findings. The main risk is concentrated in vulnerable dependencies, container image findings, and IaC misconfigurations, so the next remediation focus should be dependency upgrades, base image updates, and repeatable CI/CD imports into DefectDojo.

### Findings by severity

| Severity | Count |
|----------|------:|
| Critical | 17 |
| High | 164 |
| Medium | 168 |
| Low | 27 |
| Info | 9 |
| **Total** | **385** |

### Findings by source tool

| Tool / Test | Active findings | Mitigated | False Positive | Risk Accepted |
|-------------|----------------:|----------:|---------------:|--------------:|
| Anchore Grype | 104 | 0 | 0 | 0 |
| Trivy Scan — Lab 4 | 113 | 0 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 |
| ZAP Scan | 0 | 0 | 0 | 0 |
| Checkov Scan | 80 | 0 | 0 | 0 |
| KICS Scan — Ansible | 10 | 0 | 0 | 0 |
| KICS Scan — Pulumi | 6 | 0 | 0 | 0 |
| Trivy Scan — Lab 7 image | 50 | 0 | 0 | 0 |
| Trivy Operator Scan | 0 | 0 | 0 | 0 |
| **Total** | **385** | **0** | **0** | **0** |

### Program metrics

- **MTTD**: 0 days for this lab baseline. Findings were detected when scan reports were imported into DefectDojo.
- **MTTR**: N/A for this run. No findings were fully remediated and closed during the lab execution.
- **Vuln-age median**: 0 days at import time. This lab created the baseline dataset.
- **Backlog trend**: Baseline created with 385 active findings. Future runs should compare against this number after remediation and re-import.
- **SLA compliance**: Baseline established. SLA tracking starts from the DefectDojo finding creation date.
- **Critical + High backlog**: 181 findings.
- **Critical + High share of backlog**: approximately 47.0% of all active findings.

### Risk-accepted items

No findings were risk-accepted during this lab run.

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| N/A | N/A | No risk acceptance was used | N/A |

In a real program, every risk-accepted item must have an owner, business justification, and explicit expiry date. Otherwise, risk acceptance becomes a way to hide vulnerabilities instead of managing them.

### Next-quarter goal

Next quarter, I would mature the OWASP SAMM Defect Management practice. This lab already centralized findings from multiple scanners in DefectDojo, but the next step is to make this repeatable in CI/CD: automatically import Grype, Trivy, Semgrep, ZAP, Checkov, KICS, and runtime security outputs after every pipeline run.

A concrete improvement would be to normalize scanner metadata before import, especially CVE/GHSA identifiers and component names. The dedup investigation showed that the same advisory, `GHSA-5mrr-rgp6-x4gr`, appeared across Grype and Trivy outputs but was not automatically collapsed into one DefectDojo finding. Fixing this would improve triage quality, reduce duplicated work, and make SLA tracking more reliable.

---

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: approximately 5 minutes
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "I turned separate security scan outputs into a vulnerability management program with centralized tracking, SLA policy, backlog metrics, and deduplication analysis."
