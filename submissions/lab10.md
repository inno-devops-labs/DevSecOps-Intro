# Lab 10 — Vulnerability Management with DefectDojo

## Task 1: DefectDojo Setup + Import

### DefectDojo version

- Version installed: `2.58.4`
- Deployment: local Docker Compose development environment
- URL: `http://localhost:8080`
- Local development administrator: `admin`
- Local development password: `admin`
- The API token is intentionally excluded from this submission.

### Product + Engagement

- Product ID: `1`
- Product name: `OWASP Juice Shop`
- Product type: `Research and Development`
- Engagement ID: `1`
- Engagement name: `Course Semester Run`
- Engagement status: `In Progress`
- Engagement type: `CI/CD`
- Target period: `2026-09-01` — `2026-12-15`

### Imports completed

| Lab | Scan type | File | Result | Findings imported |
|-----|-----------|------|--------|------------------:|
| 4 | Anchore Grype | `grype-from-sbom.json` | Successful | 105 |
| 4 | Trivy Scan | `trivy.json` | Successful | 109 |
| 5 | Semgrep JSON Report | `semgrep.json` | Successful | 22 |
| 5 | ZAP Scan | `auth-report.json` | Rejected: this parser expects XML, while the available report is JSON | 0 |
| 6 | Checkov Scan | `checkov-terraform/results_json.json` | Successful | 80 |
| 6 | KICS Scan | `kics-ansible/results.json` | Successful | 10 |
| 6 | KICS Scan | `kics-pulumi/results.json` | Successful | 6 |
| 7 | Trivy Scan | `trivy-image.json` | Successful | 50 |
| 7 | Trivy Operator Scan | `trivy-k8s.json` | Successful, valid empty result | 0 |
| 8 | Cosign verification | `verify-original.json` | Evidence artifact, not a vulnerability-report format | 0 |
| 9 | Falco runtime alerts | `falco/logs/falco.log` | Custom format; documented instead of imported | 0 |
| **Total raw findings** | | | | **382** |
| **After cross-tool deduplication** | | | | **380 canonical findings** |
| **Active after risk acceptance** | | | | **379** |

Six distinct DefectDojo scan types were successfully exercised:

1. Anchore Grype
2. Trivy Scan
3. Semgrep JSON Report
4. Checkov Scan
5. KICS Scan
6. Trivy Operator Scan

The ZAP JSON report was preserved but not misrepresented as a successful import. The installed `ZAP Scan` parser expects an XML report. The Lab 8 Cosign output is supply-chain verification evidence rather than a vulnerability scan. The Lab 9 Falco log requires a custom parser or normalized intermediary format.

### Dedup example

A concrete cross-tool correlation was completed for:

- CVE: `CVE-2026-5079`
- Affected component: `multer 1.4.5-lts.2`
- Number of source scans: `3` — Anchore Grype, Trivy Lab 4 and Trivy image Lab 7
- Scanner families: `2` — Grype and Trivy
- Canonical DefectDojo Finding ID: `70`
- Duplicate Finding IDs: `180`, `363`

Source records:

| Finding ID | Scanner/source | Final status |
|-----------:|----------------|--------------|
| 70 | Anchore Grype, Lab 4 SBOM scan | Canonical finding |
| 180 | Trivy Scan, Lab 4 scan | Duplicate of Finding 70 |
| 363 | Trivy Scan, Lab 7 image scan | Duplicate of Finding 70 |

DefectDojo's automatic scanner-specific fingerprinting did not initially merge these records because Grype and Trivy produced different titles, descriptions and hash inputs. After confirming that the CVE, package and affected version represented the same underlying issue, the records were correlated through DefectDojo's native duplicate relationship. Findings 180 and 363 are inactive and reference Finding 70 through `duplicate_finding`.

## Task 2: Governance Report

### Executive Summary

OWASP Juice Shop was assessed through six successfully exercised DefectDojo scan types, producing 382 raw finding records and 380 canonical findings after cross-tool correlation. The current active canonical backlog is 379 findings, including 17 Critical and 161 High findings. No finding has yet been recorded as mitigated, so remediation-based MTTR and closed-finding SLA performance are not measurable; however, all 370 active non-Informational findings currently remain within their assigned SLA deadlines.

### Findings by severity — active canonical findings

| Severity | Count |
|----------|------:|
| Critical | 17 |
| High | 161 |
| Medium | 166 |
| Low | 26 |
| Info | 9 |
| **Total** | **379** |

### Findings by source tool

Counts below exclude records marked as duplicates.

| Tool | Active | Mitigated | False Positive | Risk Accepted | Canonical total |
|------|-------:|----------:|---------------:|--------------:|----------------:|
| Anchore Grype | 105 | 0 | 0 | 0 | 105 |
| Trivy Scan | 157 | 0 | 0 | 0 | 157 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 | 22 |
| Checkov Scan | 80 | 0 | 0 | 0 | 80 |
| KICS Scan | 15 | 0 | 0 | 1 | 16 |
| Trivy Operator Scan | 0 | 0 | 0 | 0 | 0 |
| **Total** | **379** | **0** | **0** | **1** | **380** |

### Program metrics

- **MTTD proxy:** `0 days`
  - Finding dates and the corresponding scanner Test execution occurred on the same UTC day.
  - This measures ingestion latency in the laboratory, not the age of vulnerabilities before scanning.
- **MTTR:** `N/A`
  - There are currently zero findings with `is_mitigated=true`.
  - Duplicate correlation and Risk Acceptance are not counted as remediation.
  - Because no remediation events have been recorded, vulnerability-remediation MTTR cannot yet be calculated. This metric is not the same as DORA Time to Restore Service, which measures recovery from a production failure.
- **Vulnerability-age median for active findings:** `0 days`
  - Findings were imported and measured on the same day.
- **Raw import baseline:** `382 records`
- **Current active canonical backlog:** `379 findings`
- **Backlog delta:** `-3`
  - Two records became duplicates.
  - One Low finding was placed under a time-bound Risk Acceptance.
- **SLA-eligible active findings:** `370`
  - Informational findings are excluded.
- **Within current SLA deadline:** `370`
- **SLA breached:** `0`
- **Current open-backlog SLA compliance:** `100%`
- **Closed-finding SLA compliance:** `N/A`
  - There are no completed remediation events yet.

Applied SLA matrix:

| Severity | Remediation target |
|----------|-------------------:|
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

### Risk-accepted items

| Finding | ID | Severity | Source | Reason | Expiry date |
|---------|---:|----------|--------|--------|-------------|
| Supply-Chain: Unpinned Package Version | 326 | Low | KICS Scan | Temporarily accepted for the isolated and ephemeral local training environment. It contains no production data and is not operated as a production service. The finding must be reviewed during the next IaC hardening iteration. | 2026-09-30 |

Risk Acceptance details:

- Risk Acceptance ID: `1`
- Decision: Accept
- Security recommendation: Mitigate
- Reactivate finding after expiration: enabled
- Restart SLA after expiration: enabled
- All risk-accepted findings have an explicit expiration date.

### Next-quarter goal — OWASP SAMM Defect Management

The next-quarter priority is to mature the OWASP SAMM **Implementation / Defect Management** practice. The current program aggregates and prioritizes findings, but it has 379 active findings and zero recorded remediations, leaving MTTR unmeasurable. The next maturity step is to assign owners, create severity-based remediation tickets, verify fixes through re-imports, and target closure of every Critical finding within 24 hours and every High finding within seven days.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Estimated runtime from word count: approximately `4:20–4:50`
- Practiced read-aloud runtime: `4:36`
- Two anticipated Q&A questions covered: yes
- Strongest claim: “I converted 382 scanner records into a governed backlog with cross-tool correlation, explicit SLA deadlines and expiring risk acceptance rather than treating every scanner result as an independent vulnerability.”
