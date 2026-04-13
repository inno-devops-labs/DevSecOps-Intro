# Lab 10 Submission — Vulnerability Management & Response with DefectDojo

## Student

- GitHub username: `ellilin`
- Branch: `feature/lab10`
- Date: `2026-04-13`
- Environment: macOS + Docker Desktop + local OWASP DefectDojo on `http://localhost:8080`

## Task 1 — DefectDojo Local Setup

DefectDojo was stood up locally from the upstream Docker Compose stack cloned into `labs/lab10/setup/django-DefectDojo/`.

Setup evidence:

- [setup-evidence.md](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/setup/setup-evidence.md)
- [compose-ps.txt](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/setup/compose-ps.txt)
- [admin-password-masked.txt](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/setup/admin-password-masked.txt)

Created context in DefectDojo:

- Product Type: `Engineering`
- Product: `Juice Shop`
- Engagement: `Labs Security Testing`

Important implementation notes:

- `localhost:8080` needed `NO_PROXY='*'` in this environment so API traffic bypassed the default proxy.
- The provided `labs/lab10/imports/run-imports.sh` script was patched to work with macOS Bash 3.x and to pick the correct parser names from this DefectDojo instance.
- The saved ZAP artifact from Lab 5 was JSON, but the available `ZAP Scan` importer expected XML, so the workflow converts it to `labs/lab10/imports/zap-report-noauth.xml` before import.

## Task 2 — Import Prior Findings

The import workflow used the repository helper:

```bash
NO_PROXY='*' \
DD_API='http://localhost:8080/api/v2' \
DD_TOKEN='<local api token>' \
DD_PRODUCT_TYPE='Engineering' \
DD_PRODUCT='Juice Shop' \
DD_ENGAGEMENT='Labs Security Testing' \
bash labs/lab10/imports/run-imports.sh
```

Successful import artifacts:

- [import-zap-report-noauth.xml.json](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/imports/import-zap-report-noauth.xml.json)
- [import-semgrep-results.json.json](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/imports/import-semgrep-results.json.json)
- [import-trivy-vuln-detailed.json.json](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/imports/import-trivy-vuln-detailed.json.json)
- [import-nuclei-results.json.json](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/imports/import-nuclei-results.json.json)
- [import-grype-vuln-results.json.json](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/imports/import-grype-vuln-results.json.json)

Imported tests in the engagement:

- `ZAP Scan` — 12 findings
- `Semgrep JSON Report` — 25 findings
- `Trivy Scan` — 147 findings
- `Nuclei Scan` — 25 findings
- `Anchore Grype` — 122 findings

Total imported findings in DefectDojo: `331`

## Task 3 — Report + Metrics Package

Generated artifacts:

- [metrics-snapshot.md](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/report/metrics-snapshot.md)
- [dojo-report.html](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/report/dojo-report.html)
- [findings.csv](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/report/findings.csv)
- [summary.json](/Users/mazzz3r/study/devsecops/DevSecOps-Intro/labs/lab10/report/summary.json)

### Metrics Snapshot

- Active findings: `331`
- Verified findings: `143`
- Mitigated findings: `0`
- Severity mix among active findings:
  - Critical: `21`
  - High: `154`
  - Medium: `89`
  - Low: `28`
  - Info: `39`

### Summary Highlights

- The vulnerability backlog is dominated by higher-severity infrastructure and dependency findings: `154` High and `21` Critical findings remain active.
- Container and package scanners contribute most of the volume, with `Trivy` adding `147` findings and `Grype` adding `122`, while application-focused tools contributed `25` findings each from `Semgrep` and `Nuclei`, plus `12` from `ZAP`.
- `143` findings are marked as verified, all coming from the Trivy import, while none are mitigated yet, so the dashboard currently represents a pure baseline backlog rather than a remediation progress snapshot.
- SLA outlook is active in this local instance: `21` findings are due within the next 14 days and `0` are already overdue.
- The most frequent recurring weakness categories were `CWE-1333` (`29` findings), `CWE-407` (`13`), `CWE-79` (`11`), `CWE-22` (`11`), and `CWE-200` (`9`).

## Deliverable Checklist

- [x] Task 1 — Dojo setup and structure
- [x] Task 2 — Imports completed (multi-tool)
- [x] Task 3 — Report + metrics package

## Bonus Task

No separate bonus task was listed in `labs/lab10.md`.
