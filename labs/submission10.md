# Lab 10 - Vulnerability Management and Response with DefectDojo

## Overview
For this lab I deployed a local OWASP DefectDojo instance with Docker Compose, created a product structure for the Juice Shop target, generated security scan artifacts, imported the supported findings into DefectDojo, and produced a reporting package under `labs/lab10/`.

Target context used in DefectDojo:
- Product Type: `Engineering`
- Product: `Juice Shop`
- Engagement: `Labs Security Testing`

## Task 1 - DefectDojo local setup
DefectDojo was started locally from the official `django-DefectDojo` Docker Compose stack. The following containers reached the expected state during startup:
- `django-defectdojo-postgres-1`
- `django-defectdojo-valkey-1`
- `django-defectdojo-celeryworker-1`
- `django-defectdojo-uwsgi-1`
- `django-defectdojo-celerybeat-1`
- `django-defectdojo-nginx-1`
- `django-defectdojo-initializer-1` (completed and exited)

The UI became reachable at `http://localhost:8080`. The admin password was not extracted automatically from the initializer logs, but the stack itself started successfully and the API was reachable for subsequent imports.

## Task 2 - Import prior findings
I imported the findings into the same DefectDojo engagement using the API-based batch import flow.

### Import results
| Tool | Result | Scan type used | Notes |
|---|---|---|---|
| ZAP | Failed | N/A | DefectDojo rejected the file because it expected XML format for the ZAP parser. |
| Semgrep | Success | `Semgrep JSON Report` | Imported successfully. |
| Trivy | Success | `Trivy Scan` | Imported successfully. |
| Nuclei | Skipped | N/A | No optional Nuclei report was available at import time. |
| Grype | Success | `Anchore Grype` | Imported successfully. |

### Additional scan generation notes
- ZAP scan execution itself completed and produced passive findings, but the DefectDojo import step did not complete because the available ZAP artifact did not match the format expected by the parser.
- Semgrep completed successfully and reported **18 findings** in the codebase scan.
- Trivy completed successfully and produced a vulnerability report for the Juice Shop image.
- Nuclei report generation did not complete in the automation run because templates were not available in the container environment.
- Grype completed successfully and was imported into DefectDojo.

## Task 3 - Reporting and program metrics
I generated the reporting artifacts required for the lab and stored them under `labs/lab10/report/`.

### Metrics snapshot
Date captured: `2026-04-12 11:15:45`

Active findings by severity:
- Critical: **18**
- High: **102**
- Medium: **75**
- Low: **20**
- Informational: **9**

Status summary:
- Total findings: **224**
- Verified: **125**
- Mitigated: **0**

### Key highlights
- The current engagement contains **224 total findings**, with the largest concentration in the **High** and **Medium** severity ranges.
- The active severity mix is **18 Critical / 102 High / 75 Medium / 20 Low / 9 Informational**, which indicates a backlog dominated by high-priority items.
- **125 findings are verified** and **0 are mitigated**, so the current state reflects imported and triaged results rather than remediation progress.
- Based on the generated stakeholder report, the most frequent CWE categories are **CWE-22 (11 findings)**, **CWE-79 (10 findings)**, **CWE-1333 (7 findings)**, **CWE-20 (6 findings)**, and **CWE-89 (6 findings)**.
- Successful imports came from **Semgrep**, **Trivy**, and **Grype**. **ZAP** import failed due to file-format mismatch, and **Nuclei** was skipped because no usable report was available.

## Generated artifacts
The following artifacts were produced for this lab:
- `labs/lab10/imports/imports-summary.md`
- `labs/lab10/imports/imports-summary.csv`
- `labs/lab10/report/metrics-snapshot.md`
- `labs/lab10/report/dojo-report.html`
- `labs/lab10/report/findings.csv`

## Notes / limitations
- ZAP findings were **not imported** into DefectDojo because the parser expected an XML report, while the available artifact did not match that requirement.
- Nuclei findings were **not imported** because the automation run did not have the required templates and therefore did not produce a usable report.
- No mitigation work was performed in this lab; the result is a management and reporting snapshot of imported findings.

## Submission summary
This lab demonstrates a working local DefectDojo deployment, successful multi-tool imports for Semgrep, Trivy, and Grype, and a stakeholder-facing reporting package with a metrics snapshot and findings export.
