# Lab 10 Submission - Vulnerability Management & Response with DefectDojo

## Setup Evidence

- DefectDojo was cloned from `https://github.com/DefectDojo/django-DefectDojo` and started locally with Docker Compose.
- Compose compatibility check passed.
- The local UI/API was exposed on `http://localhost:8081` because `localhost:8080` was already occupied by a local `kubectl` port-forward.
- Core services were running: `postgres`, `valkey`, `initializer`, `uwsgi`, `nginx`, `celeryworker`, and `celerybeat`.
- Product Type/Product/Engagement were auto-created by the importer as `Engineering` / `Juice Shop` / `Labs Security Testing`.

## Import Results

- ZAP unauthenticated baseline import: 10 findings from `labs/lab5/zap/zap-report-noauth.xml`.
- Semgrep import: 9 findings from `labs/lab5/semgrep/semgrep-results.json` using the Lab 10 local Semgrep ruleset.
- Trivy filesystem import: 0 vulnerability findings from `labs/lab4/trivy/trivy-vuln-detailed.json`.
- Nuclei import: 21 findings from `labs/lab5/nuclei/nuclei-results.json`.
- Grype was skipped because `labs/lab4/syft/grype-vuln-results.json` was not present.

## Metrics Summary

- Baseline total is 40 active findings: 5 High, 7 Medium, 5 Low, and 23 Informational; 0 Critical.
- Open vs. closed status is 40 open and 0 closed overall: Critical 0/0, High 5/0, Medium 7/0, Low 5/0, Informational 23/0.
- No findings are currently verified or mitigated, so this is a pre-triage baseline for the vulnerability management workflow.
- Tool contribution is Nuclei 21, ZAP 10, Semgrep 9, Trivy 0, and Grype 0.
- No findings are due within the next 14 days; High findings are due on 2026-05-27, Medium findings on 2026-07-26, and Low findings on 2026-08-25.
- The most recurring CWE categories are CWE-798 hardcoded credentials/secrets, CWE-601 open redirect, CWE-693 protection mechanism/header issues, and CWE-200 information exposure.

## Exported Artifacts

- `labs/lab10/report/metrics-snapshot.md`
- `labs/lab10/report/dojo-report.html`
- `labs/lab10/report/findings.csv`
- `labs/lab10/report/findings-api.json`
- `labs/lab10/report/tests-api.json`
- `labs/lab10/imports/import-zap-report-noauth.xml.json`
- `labs/lab10/imports/import-semgrep-results.standard.json`
- `labs/lab10/imports/import-trivy-vuln-detailed.json.json`
- `labs/lab10/imports/import-nuclei-results.json.json`

## Submission Checklist

- [x] Task 1 - DefectDojo local setup and evidence captured.
- [x] Task 2 - Multi-tool imports completed for available ZAP, Semgrep, Trivy, and Nuclei reports.
- [x] Task 3 - Metrics snapshot, HTML report, findings CSV, API exports, and stakeholder summary captured.
- [x] Sensitive values such as the admin password and API token were not committed.
