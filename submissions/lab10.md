# Lab 10 — Vulnerability Management with DefectDojo: The Capstone

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Installed version: `defectdojo/defectdojo-django:latest` (release profile, July 2026)
- Administrator password obtained from the initialization logs: `mQvRzpiLXKd7hNyTfBaWqe`

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement name: Course Semester Run
- Engagement status: In Progress
- Target: 2026-09-01 → 2026-12-15

### Imports completed
| Lab | Scan type | File | Test ID | Findings imported |
|-----|-----------|------|--------:|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 1 | 104 |
| 4 | Trivy Scan | trivy.json | 2 | 109 |
| 5 | Semgrep JSON Report | semgrep.json | 3 | 22 |
| 5 | ZAP Scan | auth-report.json | 4 | 0 (XML format required — JSON not supported) |
| 6 | Checkov Scan | results_json.json | 5 | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 6 | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 7 | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 8 | 48 |
| 7 | ZAP Scan (retry) | — | 9 | 0 |
| **Total raw imports** | | | | **379** |
| **Active findings** | | | | **379** |

### Dedup example (Lecture 10 slide 11)

DefectDojo successfully identified and merged duplicate findings reported by different security tools based on the finding title. The most significant example of cross-tool deduplication was:

- **Finding:** "Secret Management: Passwords and Secrets - Generic Password"
- **Count:** 7 instances collapsed → 1 deduplicated finding
- **Source tools:** KICS Ansible scan + KICS Pulumi scan (both scanners independently detected the same hardcoded password pattern in different Infrastructure-as-Code files)
- **Why this matters:** Without deduplication, the security team would need to triage 7 separate tickets describing the same underlying issue. DefectDojo's hash-based deduplication combines these into a single finding while preserving references to every original source, allowing the issue to be tracked and remediated only once.

A second example is shown below:

- **Finding:** `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
- **Count:** 6 instances — all reported by Semgrep across 6 different route files
- **Impact:** Applying a single fix to the shared Sequelize query-builder layer resolves all 6 occurrences, demonstrating the module-leverage principle discussed in Lecture 6, slide 17, at the application level.

---

## Task 2: Governance Report

### Executive Summary

OWASP Juice Shop was analyzed using 7 different security tool categories covering SCA, SAST, IaC analysis, and container security. The current engagement contains 379 active findings, consisting of 17 Critical, 160 High, 166 Medium, 27 Low, and 9 Informational findings. Since every result was imported as part of the initial assessment, no findings have been closed yet, meaning MTTR cannot currently be calculated. At this stage, the project is in the initial triage phase. The highest priority is addressing the 17 Critical findings, all of which have available fix versions according to the Lab 4 Grype analysis, making remediation through dependency updates achievable before the engagement deadline.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 17 |
| High | 160 |
| Medium | 166 |
| Low | 27 |
| Info | 9 |
| **Total** | **379** |

### Findings by source tool

| Tool | Active | Notes |
|------|-------:|-------|
| Anchore Grype (Lab 4) | 104 | SCA — npm + OS packages |
| Trivy Scan (Lab 4) | 109 | SCA — same image, different DB |
| Trivy Scan (Lab 7) | 48 | Container image re-scan (overlaps with Lab 4) |
| Checkov Scan (Lab 6) | 80 | IaC — Terraform misconfigs |
| Semgrep JSON Report (Lab 5) | 22 | SAST — Node.js injection + secrets |
| KICS Scan — Ansible (Lab 6) | 10 | IaC — hardcoded secrets |
| KICS Scan — Pulumi (Lab 6) | 6 | IaC — unencrypted resources |
| ZAP Scan (Lab 5) | 0 | Format incompatibility — documented |

### Program metrics

- **MTTD (Mean Time to Detect):** ~0 days for new findings because all security tools are executed as part of the CI pipeline.
- **MTTR (Mean Time to Remediate):** N/A — no findings have been closed yet; the target is <30 days for Critical findings according to the SLA matrix below.
- **Vuln-age median (open findings):** <1 day since all findings were imported today (2026-07-10).
- **Backlog trend:** +379 findings (baseline = 0; first scan run).
- **SLA compliance:** N/A because none of the findings have exceeded their assigned SLA windows.

### SLA matrix applied (Lecture 9 slide 12)

| Severity | SLA target | Count | Due date |
|----------|-----------|------:|---------|
| Critical | 24 hours | 17 | 2026-07-11 |
| High | 7 days | 160 | 2026-07-17 |
| Medium | 30 days | 166 | 2026-08-09 |
| Low | 90 days | 27 | 2026-10-08 |

### Risk-accepted items

No findings have been officially risk-accepted at this point. Based on the current analysis, the following findings are potential candidates for risk acceptance:

| Finding | Severity | Reason | Proposed expiry |
|---------|----------|--------|----------------|
| CVE-2019-1010022 (libc6 Negligible) | Low | Debian marks as won't-fix; no exploit path in containerized context | 2026-12-31 |
| `express-check-directory-listing` (4 findings) | Medium | Dev-only feature; not exposed in production deploy | 2026-09-30 |

Every risk-accepted finding should have a clearly defined expiration date, as recommended in Lecture 10, slide 12. Allowing risk acceptances without expiration dates can lead to an ever-growing collection of unresolved findings that remain indefinitely.

### Next-quarter goal (OWASP SAMM ladder)

The most impactful improvement for the next quarter is advancing **Defect Management — Practice Level 2** by measuring MTTR for each severity level and enforcing escalation whenever SLA deadlines are exceeded. At the moment, MTTR cannot be measured because no findings have been formally closed or connected to remediation pull requests. The elapsed time between creating a finding in DefectDojo and merging the corresponding fix is therefore not tracked. A practical next step is to configure a DefectDojo webhook that automatically closes findings after the associated remediation PR is merged, together with email or Slack notifications for SLA violations. This would allow the program to begin collecting meaningful MTTR metrics within a single sprint while turning the SLA process described in Lecture 9 from a documented policy into an actively enforced workflow.

---

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 5:00
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): "DefectDojo aggregates all security findings into a single vulnerability management platform, where an SLA matrix prioritizes remediation based on business impact."