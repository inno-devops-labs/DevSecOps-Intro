# Lab 10 — Vulnerability Management & Response with DefectDojo

## Task 1 — DefectDojo Local Setup (2 pts)

### Execution Summary

- Created required directories:
  - `labs/lab10/setup`
  - `labs/lab10/imports`
  - `labs/lab10/report`
- Cloned DefectDojo under:
  - `labs/lab10/setup/django-DefectDojo`
- Verified compose compatibility with:
  - `./docker/docker-compose-check.sh`
- Initial `docker compose up -d` failed due Docker network pool exhaustion.
- Added network override file to pin subnet and avoid overlap:
  - `labs/lab10/setup/docker-compose.network-override.yml`
- Started stack successfully with:
  - `docker compose -f docker-compose.yml -f ../docker-compose.network-override.yml up -d`
- Verified service status (`nginx`, `uwsgi`, `celery*`, `postgres`, `valkey`) and UI reachability:
  - `http://localhost:8080` returned HTTP `302` (login redirect expected)
- Extracted admin password from initializer logs (local only).

### Setup Evidence

- `labs/lab10/setup/compose-check.txt`
- `labs/lab10/setup/compose-up.txt`
- `labs/lab10/setup/compose-ps.txt`
- `labs/lab10/setup/initializer.log`
- `labs/lab10/setup/initializer-admin-password.txt`
- `labs/lab10/setup/ui-check.txt`
- `labs/lab10/setup/docker-compose.network-override.yml`

## Task 2 — Import Prior Findings (4 pts)

### Import Execution

- Generated API token via `/api/v2/api-token-auth/` for local automation.
- Ran batch importer:
  - `bash labs/lab10/imports/run-imports.sh`
- Parser auto-detection initially selected:
  - `Semgrep Pro JSON Report` and `Trivy Operator Scan` (both imported with 0 findings for provided files)
  - `ZAP Scan` expected XML, while provided artifact was JSON
- Corrected imports:
  - Semgrep re-imported with `Semgrep JSON Report`
  - Trivy re-imported with `Trivy Scan`
  - Converted ZAP JSON to parser-compatible XML and re-imported with `ZAP Scan`

### Final Imported Findings by Tool

- ZAP: `12`
- Semgrep: `25`
- Trivy: `147`
- Nuclei: `1`
- Grype: `122`
- Total findings in engagement: `307`

### Import Evidence

- `labs/lab10/imports/import-run.log`
- `labs/lab10/imports/import-zap-report-noauth.json.json` (initial failed JSON import response)
- `labs/lab10/imports/import-zap-report-noauth.xml.json` (successful XML import)
- `labs/lab10/imports/import-semgrep-results.json.json`
- `labs/lab10/imports/import-semgrep-json-report.retry.json`
- `labs/lab10/imports/import-trivy-vuln-detailed.json.json`
- `labs/lab10/imports/import-trivy-scan.retry.json`
- `labs/lab10/imports/import-nuclei-results.json.json`
- `labs/lab10/imports/import-grype-vuln-results.json.json`
- `labs/lab10/imports/convert-zap-json-to-xml.py`
- `labs/lab10/imports/zap-report-noauth.xml`

## Task 3 — Reporting & Program Metrics (4 pts)

### Deliverables Generated

- Metrics snapshot:
  - `labs/lab10/report/metrics-snapshot.md`
- DefectDojo engagement report payload (native API output):
  - `labs/lab10/report/dojo-report.api.json`
- Stakeholder-readable report (HTML rendering of report metrics/data):
  - `labs/lab10/report/dojo-report.html`
- Findings export (CSV):
  - `labs/lab10/report/findings.csv`

### Required Metric Summary Bullets

- **Open vs Closed by severity:** Open findings = Critical `21`, High `154`, Medium `89`, Low `27`, Informational `16`; Closed findings = `0` across all severities at this baseline snapshot.
- **Findings per tool:** Trivy `147`, Grype `122`, Semgrep `25`, ZAP `12`, Nuclei `1`.
- **SLA outlook (next 14 days):** `0` breached SLAs; `21` open findings due within the next 14 days.
- **Top recurring CWE categories:** CWE-1333 (`29`), CWE-407 (`13`), CWE-79 (`11`), CWE-22 (`11`), CWE-89 (`6`).
- **Verification/mitigation status:** `143` findings are verified, `0` findings mitigated at capture time (baseline posture prior to remediation campaign).

### Reporting Evidence

- `labs/lab10/report/dojo-report.html`
- `labs/lab10/report/dojo-report.api.json`
- `labs/lab10/report/findings.csv`
- `labs/lab10/report/metrics-snapshot.md`
- `labs/lab10/report/metrics-summary.json`
- `labs/lab10/report/findings.json`
- `labs/lab10/report/engagements.json`
- `labs/lab10/report/tests.json`
- `labs/lab10/report/test_types.json`
