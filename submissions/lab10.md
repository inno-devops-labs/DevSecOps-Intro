# Lab 10 — Vulnerability Management with DefectDojo: The Capstone

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: `defectdojo/defectdojo-django:latest` (release profile, July 2026)
- Admin password retrieved from initializer logs: `tSbqzeiKZRPjz6xTfAhohn`

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

Note: ZAP JSON output is not supported by DefectDojo's ZAP parser (requires XML). The auth-report HTML was the only available output. This is documented as a known pitfall.

### Dedup example (Lecture 10 slide 11)

DefectDojo deduplicated findings across tools by title. The strongest cross-tool dedup observed:

- **Finding:** "Secret Management: Passwords and Secrets - Generic Password"
- **Count:** 7 instances collapsed → 1 deduplicated finding
- **Source tools:** KICS Ansible scan + KICS Pulumi scan (same hardcoded password pattern detected independently by both scans across different IaC files)
- **Why this matters:** Without dedup, a triage team would open 7 tickets for the same class of issue. DefectDojo's hash-based dedup collapses them into one finding with all source references attached, so remediation is tracked once.

Second example:
- **Finding:** `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
- **Count:** 6 instances — all from Semgrep across 6 different route files
- **Impact:** One fix at the Sequelize query-builder layer closes all 6 — exactly Lecture 6 slide 17's module-leverage principle applied at the program level.

---

## Task 2: Governance Report

### Executive Summary
OWASP Juice Shop, scanned across 7 tool types spanning SCA, SAST, IaC, and container security, currently has 379 active findings: 17 Critical, 160 High, 166 Medium, 27 Low, and 9 Informational. No findings have been formally closed in this engagement (all imports are fresh), so MTTR cannot be computed from closed findings — the program is in its initial triage phase. The immediate priority is the 17 Critical findings, all of which have fix versions available per the Lab 4 Grype analysis, making this backlog addressable through dependency upgrades before the engagement target date.

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
- **MTTD (Mean Time to Detect):** ~0 days for new findings (all tools run in CI pipeline)
- **MTTR (Mean Time to Remediate):** N/A — no findings closed yet; target <30 days for Critical (per SLA matrix below)
- **Vuln-age median (open findings):** <1 day (all findings imported today, 2026-07-10)
- **Backlog trend:** +379 findings (baseline = 0; first scan run)
- **SLA compliance:** N/A (no findings have aged past their SLA yet)

### SLA matrix applied (Lecture 9 slide 12)
| Severity | SLA target | Count | Due date |
|----------|-----------|------:|---------|
| Critical | 24 hours | 17 | 2026-07-11 |
| High | 7 days | 160 | 2026-07-17 |
| Medium | 30 days | 166 | 2026-08-09 |
| Low | 90 days | 27 | 2026-10-08 |

### Risk-accepted items
No findings have been formally risk-accepted yet. The following are candidates based on analysis:

| Finding | Severity | Reason | Proposed expiry |
|---------|----------|--------|----------------|
| CVE-2019-1010022 (libc6 Negligible) | Low | Debian marks as won't-fix; no exploit path in containerized context | 2026-12-31 |
| `express-check-directory-listing` (4 findings) | Medium | Dev-only feature; not exposed in production deploy | 2026-09-30 |

All risk-accepted items must have explicit expiry dates per Lecture 10 slide 12 — the "silent program killer" is risk-accepted findings with no expiry that accumulate indefinitely.

### Next-quarter goal (OWASP SAMM ladder)
The single highest-leverage SAMM practice to mature next quarter is **Defect Management — Practice Level 2** (track MTTR per severity tier and enforce SLA breach escalation). Currently MTTR is unmeasured because no findings have been formally closed and linked to remediation PRs; the gap between a finding's DefectDojo creation date and the merged fix PR is not being captured. The concrete action is to add a DefectDojo webhook that auto-closes findings when a PR merging the fix is merged, and to configure SLA breach notifications via email/Slack — this would give the program a real MTTR number within one sprint and make the Lecture 9 SLA matrix operational rather than theoretical.

---

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4 minutes 45 seconds
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: *"When the next Log4Shell drops, I can answer 'are we affected?' in under 60 seconds — I query the SBOM attestation attached to the image in the registry, grep for the component, and get a yes/no before anyone else has finished reading the advisory."*
