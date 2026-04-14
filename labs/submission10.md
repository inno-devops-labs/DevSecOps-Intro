# Lab 10 - Vulnerability Management & Response with DefectDojo

## Scope

- Analysis date: `2026-04-14`
- DefectDojo URL: `http://localhost:8080`
- API base: `http://localhost:8080/api/v2`
- Product Type / Product / Engagement:
  - `Engineering`
  - `Juice Shop`
  - `Labs Security Testing`

## Task 1 - DefectDojo Local Setup

### Setup evidence

- DefectDojo source cloned to `labs/lab10/setup/django-DefectDojo`
- Compose compatibility check passed:
  - `labs/lab10/setup/compose-check.log`
- Stack started via Docker Compose and running on port `8080`:
  - `labs/lab10/setup/compose-up.log`
  - `labs/lab10/setup/compose-ps.txt`
- Admin password extracted from initializer logs (admin account already initialized after restart):
  - `labs/lab10/setup/initializer.log`
  - `labs/lab10/setup/admin-password.txt`

### Notes

- During execution, Docker Desktop restarted once; stack was brought back with `docker compose up -d` and reused persistent volumes.
- API token for `admin` was created from the `uwsgi` container using:
  - `python manage.py drf_create_token admin`

## Task 2 - Import Prior Findings

### Import execution

- Import helper script executed in a Linux container (to avoid Windows `bash.exe` env/line-ending issues):
  - `labs/lab10/imports/run-imports.lf.sh`
  - `labs/lab10/imports/import-run.log`
- Auto-created context succeeded (Product Type/Product/Engagement).

### Tool import results

- Semgrep (`Semgrep JSON Report`): imported successfully, `25` findings
  - Response: `labs/lab10/imports/import-semgrep-results.json.json`
- Trivy (`Trivy Operator Scan`): imported successfully, `0` findings parsed from provided file
  - Response: `labs/lab10/imports/import-trivy-vuln-detailed.json.json`
- Nuclei (`Nuclei Scan`): imported successfully, `0` findings parsed from provided file
  - Response: `labs/lab10/imports/import-nuclei-results.json.json`
- Grype (`Anchore Grype`): imported successfully, `122` findings
  - Response: `labs/lab10/imports/import-grype-vuln-results.json.json`
- ZAP:
  - Initial JSON import failed because current Dojo `ZAP Scan` parser expects XML.
  - Converted `labs/lab5/zap/zap-report-noauth.json` -> `labs/lab10/imports/zap-report-noauth.xml` and re-imported.
  - Successful response with `13` findings: `labs/lab10/imports/import-zap-report-noauth.xml.json`
  - Initial failed response retained for evidence: `labs/lab10/imports/import-zap-report-noauth.json.json`

## Task 3 - Reporting & Program Metrics

### Generated artifacts

- Metrics snapshot: `labs/lab10/report/metrics-snapshot.md`
- Stakeholder-readable report (HTML): `labs/lab10/report/dojo-report.html`
- Findings export (CSV): `labs/lab10/report/findings.csv`
- Supporting computed metrics JSON: `labs/lab10/report/metrics-summary.json`

### Required metric highlights (3-5 bullets)

- Current posture is fully open: `160` total findings, `160` active, `0` closed, `0` mitigated, `0` verified.
- Open findings by severity: `Critical 11`, `High 71`, `Medium 52`, `Low 9`, `Informational 17`.
- Findings per tool: `ZAP 13`, `Semgrep 25`, `Trivy 0`, `Nuclei 0`, `Grype 122`.
- SLA outlook: `0` breached items, `11` findings due within the next 14 days.
- Top recurring CWE/OWASP categories: `CWE-79 (7)`, `CWE-89 (6)`, `CWE-73 (4)`, `CWE-548 (4)`, `CWE-693 (3)`; mapped OWASP concentration is led by `A03:2021-Injection`.

## Deliverable Checklist

- [x] Task 1 - Dojo setup and structure
- [x] Task 2 - Imports completed (multi-tool)
- [x] Task 3 - Report + metrics package
