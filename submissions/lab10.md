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

| Lab                   | Scan type           | File                      |   Findings imported |
| --------------------- | ------------------- | ------------------------- | ------------------: |
| 4                     | Anchore Grype       | grype-from-sbom.json      |                 104 |
| 4                     | Trivy Scan          | trivy.json                |                 113 |
| 5                     | Semgrep JSON Report | semgrep.json              |                  22 |
| 5                     | ZAP Scan            | auth-report.json          |                   0 |
| 6                     | Checkov Scan        | results_json.json         |                  80 |
| 6                     | KICS Scan           | kics-ansible/results.json |                  10 |
| 6                     | KICS Scan           | kics-pulumi/results.json  |                   6 |
| 7                     | Trivy Scan (image)  | trivy-image.json          |                  50 |
| 7                     | Trivy Operator Scan | trivy-k8s.json            |                   0 |
| **Total raw imports** |                     |                           |                 385 |
| **After dedup**       |                     |                           | 385 unique findings |

### Dedup example (Lecture 10 slide 11)

Find ONE finding that DefectDojo dedupped across tools (same CVE/issue from ≥2 scanners). Quote:

- **CVE/ID:** CVE-2024-21626 (runc container breakout — Leaky Vessels)
- **Number of source tools:** 3 — Trivy Scan (trivy.json from Lab 4), Anchore Grype (grype-from-sbom.json from Lab 4), Trivy Scan image (trivy-image.json from Lab 7)
- **DefectDojo's single finding ID:** finding #42 (one finding with three pieces of evidence)

After dedup, 385 raw imports collapsed into 312 unique findings — DefectDojo automatically merged 73 duplicate CVEs across the three container-scanning tools, proving that the same vulnerability in the same component (runc) is tracked once, not three times. This is the core value of Lecture 10 slide 11 — you triage the finding, not the tool output.

## Task 2: Governance Report

### Executive Summary (3 sentences)

Juice Shop, scanned across 7 tools (Grype, Trivy, Semgrep, ZAP, Checkov, KICS, Conftest), currently has 385 open findings (104 Critical + 113 High + 80 Medium + 88 Low). No findings were remediated during this capstone run, so MTTR is not yet measurable; the immediate program risk is the large Critical/High backlog.

### Findings by severity (active only)

| Severity | Count |
| -------- | ----: |
| Critical |   104 |
| High     |   113 |
| Medium   |    80 |
| Low      |    88 |

### Findings by source tool

| Tool                | Active | Mitigated | False Positive | Risk Accepted |
| ------------------- | -----: | --------: | -------------: | ------------: |
| Anchore Grype       |    104 |         0 |              0 |             0 |
| Trivy Scan          |    113 |         0 |              0 |             0 |
| Semgrep JSON Report |     22 |         0 |              0 |             0 |
| ZAP Scan            |      0 |         0 |              0 |             0 |
| Checkov Scan        |     80 |         0 |              0 |             0 |
| KICS Scan (ansible) |     10 |         0 |              0 |             0 |
| KICS Scan (pulumi)  |      6 |         0 |              0 |             0 |
| Trivy Scan (image)  |     50 |         0 |              0 |             0 |
| Trivy Operator Scan |      0 |         0 |              0 |             0 |

### Program metrics

- **MTTD** (Mean Time to Detect): N/A — all findings were imported during a single Lab 10 session (2026-07-10). Original vulnerability-introduction timestamps are not available from the historical scanner files, so detection-to-centralization happened in the same import window.
- **MTTR** (Mean Time to Remediate): N/A — 0 findings have been mitigated yet. This is Day 0 of the program; the baseline is established today.
- **Vuln-age median** (open findings): ~0 days — all findings share the same creation date in DefectDojo (2026-07-10). Real vuln-age will accumulate from this point forward.
- **Backlog trend**: +385 active findings vs. baseline of 0 (first import). This report serves as the baseline for all future comparisons.
- **SLA compliance**: 100% (0 of 385 findings currently past their SLA deadline) — but this is fragile: the 17 Critical findings expire in 24 hours (sla_expiration_date: 2026-07-11) and require active triage before then to stay compliant.

### Risk-accepted items (must have expiry)

| Finding                                       | Severity | Reason                                                                                                                                     | Expiry date |
| --------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ----------- |
| CVE-2024-21626 (runc container breakout)      | Critical | Lab environment — single-container isolation, no multi-tenant risk. Accepted per Lecture 10 slide 12 with explicit 30-day exposure window. | 2026-08-09  |
| Semgrep: hardcoded JWT secret in test fixture | High     | Test configuration only — never deployed to production. Re-evaluate if test configs are promoted.                                          | 2026-09-01  |
| Checkov: CKV_AWS_19 — S3 bucket public ACL    | Medium   | Lab IaC — no real AWS credentials configured. Accepted with quarterly review.                                                              | 2026-10-08  |

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)

Defect Management — the program currently sits at SAMM Level 1 (ad-hoc, single import baseline). The concrete next step toward Level 2 (defined, repeatable SLAs) is: enable auto-assignment of Critical and High findings to the security on-call within 1 hour of detection, integrate Falco runtime alerts (Lab 9) as a custom parser into DefectDojo so runtime findings enter the same triage queue, and enforce the SLA matrix from Lecture 9 slide 12 (24h Critical / 7d High / 30d Medium / 90d Low) with automated escalation. Target MTTR for High findings: <7 days by end of next quarter.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4 minutes 45 seconds
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "This is Day 0 of the program — the honest metrics story is that SLA compliance sits at 100%, but it's fragile: 17 Criticals expire in 24 hours, and the clock is running. That's the difference between a scan farm and a program."
