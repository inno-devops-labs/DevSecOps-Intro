# Lab 10 — Vulnerability Management with DefectDojo

## Task 1: DefectDojo Setup + Import

### DefectDojo version

* Installed version: `2.58.4`
* Deployment model: local Docker Compose development setup
* URL: `http://localhost:8080`
* Local administrator account: `admin`
* Local administrator password: `admin`
* The API token has been deliberately omitted from this submission.

### Product + Engagement

* Product ID: `1`
* Product name: `OWASP Juice Shop`
* Product type: `Research and Development`
* Engagement ID: `1`
* Engagement name: `Course Semester Run`
* Engagement status: `In Progress`
* Engagement type: `CI/CD`
* Target period: `2026-09-01` — `2026-12-15`

### Imports completed

| Lab                                | Scan type            | File                                  | Result                                                                       |          Findings imported |
| ---------------------------------- | -------------------- | ------------------------------------- | ---------------------------------------------------------------------------- | -------------------------: |
| 4                                  | Anchore Grype        | `grype-from-sbom.json`                | Imported successfully                                                        |                        105 |
| 4                                  | Trivy Scan           | `trivy.json`                          | Imported successfully                                                        |                        109 |
| 5                                  | Semgrep JSON Report  | `semgrep.json`                        | Imported successfully                                                        |                         22 |
| 5                                  | ZAP Scan             | `auth-report.json`                    | Rejected because the parser requires XML, while the available report is JSON |                          0 |
| 6                                  | Checkov Scan         | `checkov-terraform/results_json.json` | Imported successfully                                                        |                         80 |
| 6                                  | KICS Scan            | `kics-ansible/results.json`           | Imported successfully                                                        |                         10 |
| 6                                  | KICS Scan            | `kics-pulumi/results.json`            | Imported successfully                                                        |                          6 |
| 7                                  | Trivy Scan           | `trivy-image.json`                    | Imported successfully                                                        |                         50 |
| 7                                  | Trivy Operator Scan  | `trivy-k8s.json`                      | Imported successfully as a valid empty result                                |                          0 |
| 8                                  | Cosign verification  | `verify-original.json`                | Retained as verification evidence rather than a vulnerability report         |                          0 |
| 9                                  | Falco runtime alerts | `falco/logs/falco.log`                | Recorded separately because the format requires custom handling              |                          0 |
| **Total raw findings**             |                      |                                       |                                                                              |                    **382** |
| **After cross-tool deduplication** |                      |                                       |                                                                              | **380 canonical findings** |
| **Active after risk acceptance**   |                      |                                       |                                                                              |                    **379** |

Six separate DefectDojo scan types were successfully tested:

1. Anchore Grype
2. Trivy Scan
3. Semgrep JSON Report
4. Checkov Scan
5. KICS Scan
6. Trivy Operator Scan

The ZAP JSON report was retained, but it was not presented as a successful import because the installed `ZAP Scan` parser only accepts XML. The Lab 8 Cosign file represents software supply-chain verification evidence rather than vulnerability data. The Lab 9 Falco log would require either a custom parser or conversion into a supported intermediate format.

### Dedup example

A specific cross-scanner correlation was completed for:

* CVE: `CVE-2026-5079`
* Affected component: `multer 1.4.5-lts.2`
* Number of source scans: `3` — Anchore Grype, Trivy Lab 4 and Trivy image Lab 7
* Scanner families: `2` — Grype and Trivy
* Canonical DefectDojo Finding ID: `70`
* Duplicate Finding IDs: `180`, `363`

Source records:

| Finding ID | Scanner/source                 | Final status            |
| ---------: | ------------------------------ | ----------------------- |
|         70 | Anchore Grype, Lab 4 SBOM scan | Canonical finding       |
|        180 | Trivy Scan, Lab 4 scan         | Duplicate of Finding 70 |
|        363 | Trivy Scan, Lab 7 image scan   | Duplicate of Finding 70 |

DefectDojo did not merge these findings automatically because Grype and Trivy generated different titles, descriptions, and fingerprint inputs. After verifying that the CVE, package, and affected version referred to the same vulnerability, the findings were linked through DefectDojo’s built-in duplicate relationship. Findings 180 and 363 are now inactive and point to Finding 70 through `duplicate_finding`.

## Task 2: Governance Report

### Executive Summary

OWASP Juice Shop was evaluated through six DefectDojo scan types. The imports produced 382 raw records, which were reduced to 380 canonical findings after cross-tool correlation. The current active backlog contains 379 findings, including 17 Critical and 161 High issues. No findings have been marked as mitigated, so remediation MTTR and closed-finding SLA performance cannot yet be calculated. At the same time, all 370 active non-Informational findings remain within their assigned SLA windows.

### Findings by severity — active canonical findings

| Severity  |   Count |
| --------- | ------: |
| Critical  |      17 |
| High      |     161 |
| Medium    |     166 |
| Low       |      26 |
| Info      |       9 |
| **Total** | **379** |

### Findings by source tool

The values below do not include findings marked as duplicates.

| Tool                |  Active | Mitigated | False Positive | Risk Accepted | Canonical total |
| ------------------- | ------: | --------: | -------------: | ------------: | --------------: |
| Anchore Grype       |     105 |         0 |              0 |             0 |             105 |
| Trivy Scan          |     157 |         0 |              0 |             0 |             157 |
| Semgrep JSON Report |      22 |         0 |              0 |             0 |              22 |
| Checkov Scan        |      80 |         0 |              0 |             0 |              80 |
| KICS Scan           |      15 |         0 |              0 |             1 |              16 |
| Trivy Operator Scan |       0 |         0 |              0 |             0 |               0 |
| **Total**           | **379** |     **0** |          **0** |         **1** |         **380** |

### Program metrics

* **MTTD proxy:** `0 days`

  * Finding creation dates and the related scanner Test executions occurred on the same UTC date.
  * This value represents ingestion delay in the lab environment rather than the time vulnerabilities existed before discovery.
* **MTTR:** `N/A`

  * No findings currently have `is_mitigated=true`.
  * Duplicate linking and Risk Acceptance are not treated as remediation actions.
  * Since there are no recorded remediation events, vulnerability MTTR cannot yet be calculated. This should not be confused with DORA Time to Restore Service, which measures recovery from production incidents.
* **Vulnerability-age median for active findings:** `0 days`

  * Findings were imported and evaluated on the same day.
* **Raw import baseline:** `382 records`
* **Current active canonical backlog:** `379 findings`
* **Backlog delta:** `-3`

  * Two findings were classified as duplicates.
  * One Low-severity finding was placed under temporary Risk Acceptance.
* **SLA-eligible active findings:** `370`

  * Informational findings are not included.
* **Within current SLA deadline:** `370`
* **SLA breached:** `0`
* **Current open-backlog SLA compliance:** `100%`
* **Closed-finding SLA compliance:** `N/A`

  * No remediation activities have been completed yet.

Applied SLA matrix:

| Severity | Remediation target |
| -------- | -----------------: |
| Critical |           24 hours |
| High     |             7 days |
| Medium   |            30 days |
| Low      |            90 days |

### Risk-accepted items

| Finding                                |  ID | Severity | Source    | Reason                                                                                                                                                                                                                                                                | Expiry date |
| -------------------------------------- | --: | -------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| Supply-Chain: Unpinned Package Version | 326 | Low      | KICS Scan | Temporarily accepted because the issue exists only in an isolated, short-lived local training environment. The environment contains no production data and is not used as a production service. The finding must be reconsidered during the next IaC hardening cycle. | 2026-09-30  |

Risk Acceptance details:

* Risk Acceptance ID: `1`
* Decision: Accept
* Security recommendation: Mitigate
* Reactivate finding after expiration: enabled
* Restart SLA after expiration: enabled
* Every risk-accepted finding includes a defined expiration date.

### Next-quarter goal — OWASP SAMM Defect Management

The next-quarter objective is to improve the OWASP SAMM **Implementation / Defect Management** practice. The program already centralizes and prioritizes findings, but it still contains 379 active issues and no documented remediations, which prevents MTTR from being measured. The next maturity step is to assign accountable owners, create remediation tickets based on severity, confirm fixes through re-imports, and aim to close every Critical finding within 24 hours and every High finding within seven days.

## Bonus: Interview Walkthrough

* Walkthrough script: see `submissions/lab10-walkthrough.md`
* Estimated runtime based on word count: approximately `4:20–4:50`
* Practiced read-aloud runtime: `4:36`
* Two expected Q&A questions included: yes
* Strongest claim: “I transformed 382 scanner records into a governed vulnerability backlog with cross-tool deduplication, defined SLA targets, and time-limited risk acceptance instead of treating every scanner result as a separate issue.”
