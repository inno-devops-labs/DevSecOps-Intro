# Lab 10 Submission - Vulnerability Management and Response with DefectDojo

## Task 1 - DefectDojo Setup

Setup artifacts:

- Upstream clone and local stack: [labs/lab10/setup/django-DefectDojo](/Users/marianikolashina/DevSecOps-Intro/labs/lab10/setup/django-DefectDojo)
- Import helper: [labs/lab10/imports/run-imports.sh](/Users/marianikolashina/DevSecOps-Intro/labs/lab10/imports/run-imports.sh)

Local setup evidence:

- `docker compose ps` showed the DefectDojo stack running with `nginx`, `uwsgi`, `celeryworker`, `celerybeat`, `postgres`, and `valkey`.
- The local DefectDojo instance contains Product Type `Engineering`, Product `Juice Shop`, and Engagement `Labs Security Testing`.
- The engagement now contains imports for all five required tool types: `Trivy Scan`, `Anchore Grype`, `ZAP Scan`, `Semgrep JSON Report`, and `Nuclei Scan`.

## Task 2 - Import Results

Saved import responses:

- ZAP compatibility XML used for import: [labs/lab10/imports/zap-report-noauth.xml](/Users/marianikolashina/DevSecOps-Intro/labs/lab10/imports/zap-report-noauth.xml)
- ZAP import response: [labs/lab10/imports/import-zap-report-noauth.json.json](/Users/marianikolashina/DevSecOps-Intro/labs/lab10/imports/import-zap-report-noauth.json.json)
- Semgrep import response: [labs/lab10/imports/import-semgrep-results.json.json](/Users/marianikolashina/DevSecOps-Intro/labs/lab10/imports/import-semgrep-results.json.json)
- Nuclei import response: [labs/lab10/imports/import-nuclei-results.json.json](/Users/marianikolashina/DevSecOps-Intro/labs/lab10/imports/import-nuclei-results.json.json)
- Trivy import response: [labs/lab10/imports/import-trivy-vuln-detailed.json.json](/Users/marianikolashina/DevSecOps-Intro/labs/lab10/imports/import-trivy-vuln-detailed.json.json)
- Grype import response: [labs/lab10/imports/import-grype-vuln-results.json.json](/Users/marianikolashina/DevSecOps-Intro/labs/lab10/imports/import-grype-vuln-results.json.json)

Observed import state:

- `ZAP Scan` import created `12` findings: `2` Medium, `6` Low, and `4` Informational.
- `Semgrep JSON Report` import created `25` findings: `7` High and `18` Medium.
- `Nuclei Scan` import created `1` Medium finding.
- `Trivy Scan` import created `147` findings: `10` Critical, `83` High, `36` Medium, and `18` Low. `143` of those findings are marked verified in DefectDojo.
- `Anchore Grype` import created `120` findings: `11` Critical, `62` High, `32` Medium, `3` Low, and `12` Informational. These findings are active but not verified.
- The combined engagement contains `305` findings across all five required tool types.
- This DefectDojo build only accepts ZAP XML for `ZAP Scan`, so I converted the Lab 5 JSON report to a schema-compatible XML file before importing it.
- An initial failed JSON-based ZAP attempt left an empty `ZAP Scan` test object with `0` findings; the successful ZAP findings are in the later XML-based import and are the ones reflected in the metrics below.

## Task 3 - Reporting and Metrics

Reporting artifacts:

- Metrics snapshot: [labs/lab10/report/metrics-snapshot.md](/Users/marianikolashina/DevSecOps-Intro/labs/lab10/report/metrics-snapshot.md)
- Engagement report export: [labs/lab10/report/dojo-report.html](/Users/marianikolashina/DevSecOps-Intro/labs/lab10/report/dojo-report.html)
- Findings CSV export: [labs/lab10/report/findings.csv](/Users/marianikolashina/DevSecOps-Intro/labs/lab10/report/findings.csv)

Metric summary highlights:

- Open vs. closed by severity: `305` findings are open and `0` are closed. Severity mix is `21` Critical, `152` High, `89` Medium, `27` Low, and `16` Informational.
- Findings per tool: `Trivy Scan = 147`, `Anchore Grype = 120`, `Semgrep JSON Report = 25`, `ZAP Scan = 12`, and `Nuclei Scan = 1`.
- Verification and mitigation status: `143` findings are verified, `0` are mitigated, and `0` are overdue as of 2026-04-13.
- SLA outlook: `21` active Critical findings are due within the next 14 days, all with an SLA deadline of 2026-04-20.
- Top recurring CWE categories in the imported data are `CWE-1333 (29)`, `CWE-407 (13)`, `CWE-22 (11)`, `CWE-79 (11)`, and a tie at `6` each for `CWE-20`, `CWE-89`, `CWE-674`, and `CWE-1321`. OWASP category tags were not consistently populated in the exported finding data, so CWE recurrence was used as the stable comparison metric.

## Acceptance Criteria Check

- [x] DefectDojo runs locally and reporting artifacts were exported
- [x] Product Type, Product, and Engagement are configured
- [x] Imports completed for ZAP, Semgrep, Trivy, Nuclei, and Grype
- [x] `labs/lab10/report/metrics-snapshot.md`, `dojo-report.html`, and `findings.csv` exist
- [x] All current Lab 10 artifacts are saved under `labs/lab10/`
