# Lab 10 — Vulnerability Management & Response with DefectDojo

## Goal

Stand up DefectDojo locally, import prior lab findings, and produce a stakeholder-ready reporting and metrics package.

## Setup

- DefectDojo is running locally from `labs/lab10/setup/django-DefectDojo`
- UI is available at `http://localhost:8080`
- Admin login was created by the initializer
- API token was obtained from the local Dojo API and used for imports

## Imports

- ZAP import was converted from JSON to Dojo-compatible XML before upload
- Imported findings into product `Juice Shop Lab10` and engagement `Labs Security Testing Lab10`
- Imported tools:
  - ZAP Scan
  - Semgrep JSON Report
  - Trivy Operator Scan
  - Nuclei Scan
  - Anchore Grype

## Metrics Summary

- The engagement currently contains `159` active findings.
- Severity mix for active findings:
  - Critical: `11`
  - High: `69`
  - Medium: `52`
  - Low: `9`
  - Informational: `18`
- Findings by tool:
  - Grype: `120`
  - Semgrep: `25`
  - ZAP: `12`
  - Nuclei: `2`
  - Trivy: `0`
- SLA outlook:
  - `11` findings are due within 14 days
  - `0` findings are already breached

## Key Observations

- Grype dominates the imported volume, which is expected because the SBOM-based vulnerability set is broad.
- Semgrep contributes the next largest share, with several medium-severity findings in application code.
- ZAP and Nuclei surface mostly web-facing issues, while Trivy had no active findings in this dataset.
- All imported findings are currently active; none are verified, mitigated, or marked as false positive.

## Artifacts

- `labs/lab10/report/metrics-snapshot.md`
- `labs/lab10/report/dojo-report.html`
- `labs/lab10/report/findings.csv`
- `labs/lab10/imports/run-imports.sh`
- `labs/lab10/imports/zap-report-noauth.xml`
