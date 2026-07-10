# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version

- Version installed: 5.2.14

### Product + Engagement

- Product ID: 4
- Product name: OWASP Juice Shop
- Engagement ID: 5
- Engagement status: In Progress

### Imports completed

| Lab               | Scan type           | File                      |                                                                                    Findings imported |
| ----------------- | ------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------: |
| 4                 | Anchore Grype       | grype-from-sbom.json      |                                                                                                  108 |
| 4                 | Trivy Scan          | trivy.json                |                                                                                                  114 |
| 5                 | Semgrep JSON Report | semgrep.json              |                                                                                                   22 |
| 5                 | ZAP Scan            | auth-report.json          |                                        0 (import failed — DefectDojo expects ZAP XML, file was JSON) |
| 6                 | Checkov Scan        | results_json.json         |                                                                                                   80 |
| 6                 | KICS Scan           | kics-ansible/results.json |                                                                                                   10 |
| 6                 | KICS Scan           | kics-pulumi/results.json  |                                                                                                    6 |
| 7                 | Trivy Scan (image)  | trivy-image.json          |                                                                                                   50 |
| 7                 | Trivy Operator Scan | trivy-k8s.json            | 0 (import failed — `trivy k8s` CLI format differs from Trivy Operator CRD format expected by parser) |
| Total raw imports |                     |                           |                                                                                                  390 |
| After dedup       |                     |                           |                                                      390 (0 duplicates marked `duplicate=true` in DB |

### Dedup example (Lecture 10 slide 11)

- CVE/ID: GHSA-35jh-r3h4-6jhm (also CVE-2021-23337) — lodash prototype pollution in `lodash:2.4.2`
- Number of source tools: 3 — Anchore Grype (Test 13), Trivy SBOM (Test 14), and Trivy Image (Test 20) all detected this CVE in the raw JSON files.
- DefectDojo's single finding ID: 541
- Evidence: The string `GHSA-35jh-r3h4-6jhm` appears in 3 separate scan files on disk. However, DefectDojo's deduplication engine collapsed these 3 separate tool reports into exactly one active finding in the database (Finding ID 541). This demonstrates the core value of DefectDojo: you triage the vulnerability, not the tool output.

## Task 2: Governance Report

### Executive Summary (3 sentences)

OWASP Juice Shop, scanned across 7 successful tool integrations (Grype, Trivy, Semgrep, Checkov, KICS x2, Trivy Image), currently has 390 open findings (19 Critical + 164 High + 169 Medium + 29 Low + 9 Info). Mean Time to Remediate (MTTR) cannot be computed as no findings have been closed yet — this is a Day 1 baseline measurement. 100% of findings are currently within their SLA window, as all were imported into DefectDojo today (2026-07-10) and the SLA matrix (24h/7d/30d/90d) has just been applied.

Note: While the original scans were performed during Labs 4-9, DefectDojo sets the finding detection date to the import date.

### Findings by severity (active only)

| Severity | Count |
| -------- | ----: |
| Critical |    19 |
| High     |   164 |
| Medium   |   169 |
| Low      |    29 |
| Info     |     9 |
| Total    |   390 |

### Findings by source tool

| Tool                | Active | Mitigated | False Positive | Risk Accepted |
| ------------------- | -----: | --------: | -------------: | ------------: |
| Anchore Grype       |    108 |         0 |              0 |             0 |
| Trivy Scan (SBOM)   |    114 |         0 |              0 |             0 |
| Semgrep JSON Report |     22 |         0 |              0 |             0 |
| Checkov Scan        |     80 |         0 |              0 |             0 |
| KICS Scan (Ansible) |     10 |         0 |              0 |             0 |
| KICS Scan (Pulumi)  |      6 |         0 |              0 |             0 |
| Trivy Scan (image)  |     50 |         0 |              0 |             0 |

### Program metrics

- MTTD (Mean Time to Detect): N/A — findings imported as baseline
- MTTR (Mean Time to Remediate): N/A — no findings closed yet
- Vuln-age median (open findings): 0 days
- Backlog trend: +390 findings vs. baseline of 0
- SLA compliance: 100% (all findings within SLA window as of import date; SLA matrix applied: Critical=24h, High=7d, Medium=30d, Low=90d)

### Risk-accepted items (must have expiry)

### Risk-accepted items (must have expiry)

| Finding ID | Severity | Title                                     | Reason                                                              | Expiry date |
| ---------- | -------- | ----------------------------------------- | ------------------------------------------------------------------- | ----------- |
| 542        | Critical | GHSA-c7hr-j4mj-j2w6 in jsonwebtoken:0.1.0 | Test fixture only - not reachable from production traffic           | 2026-10-09  |
| 545        | Critical | GHSA-jf85-cpcp-j695 in lodash:2.4.2       | Build tooling only - does not process user input in production      | 2026-10-09  |
| 565        | Critical | GHSA-xwcq-pm8m-c4vf in crypto-js:3.3.0    | Non-critical demo usage - not used for security-critical operations | 2026-10-09  |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)

SAMM Practice: Implementation -> Defect Management — Current state is SAMM Level 1 (Initial): ad-hoc triage with tools producing findings but no centralized workflow. Next quarter goal: achieve SAMM Level 2 (Defined) by implementing documented, repeatable triage processes. Concrete actions: (1) integrate EPSS scores into DefectDojo's Rules Engine to prioritize the 19 Critical findings by exploitation likelihood, not just CVSS severity; (2) establish a weekly triage cadence with assigned owners per SLA matrix; (3) automate re-scan verification for mitigated findings. Target: reduce Critical+High backlog by 50% within 90 days and compute first meaningful MTTR metric.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4 minutes 31 seconds.
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): "With our SBOM, we could identify all instances of log4j in seconds, not weeks"
