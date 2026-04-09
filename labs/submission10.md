# Vulnerability Management & Response with DefectDojo

## DefectDojo Setup

OWASP DefectDojo was started locally with Docker Compose and was reachable at `http://localhost:8080`. The target structure was created as `Engineering` -> `Juice Shop` -> `Labs Security Testing`. At the time of capture, all 6 core services were running: `nginx`, `uwsgi`, `postgres`, `valkey`, `celeryworker`, and `celerybeat`.

Evidence: `labs/lab10/setup/compose-ps.txt`.

## Import Results

- ZAP: `labs/lab5/zap/zap-report-noauth.json` was converted to `labs/lab10/imports/zap-report-noauth.xml` because the current DefectDojo parser accepts XML only; import result: `12 findings`, `test_id=6`.
- Semgrep: `labs/lab5/semgrep/semgrep-results.json` imported successfully; result: `25 findings`, `test_id=2`.
- Trivy: `labs/lab4/trivy/trivy-vuln-detailed.json` imported successfully; result: `147 findings`, `test_id=3`.
- Nuclei: `labs/lab5/nuclei/nuclei-results.json` imported successfully; result: `1 finding`, `test_id=4`.
- Grype: `labs/lab4/syft/grype-vuln-results.json` imported successfully; result: `122 findings`, `test_id=5`.

Evidence: `labs/lab10/imports/import-zap-report-noauth.xml.json`, `labs/lab10/imports/import-semgrep-results.json.json`, `labs/lab10/imports/import-trivy-vuln-detailed.json.json`, `labs/lab10/imports/import-nuclei-results.json.json`, `labs/lab10/imports/import-grype-vuln-results.json.json`.

## Key Metrics

- Open vs. closed by severity: Critical `21/0`, High `154/0`, Medium `88/0`, Low `27/0`, Info `17/0`.
- Findings per tool: Trivy `147`, Grype `122`, Semgrep `25`, ZAP `12`, Nuclei `1`.
- The engagement contains `307` imported findings; all `307` remain open, `143` are marked verified, and `0` are mitigated.
- SLA tracking is active for the imported data: `21` Critical findings are due within the next 14 days (by `2026-04-16`), and `0` findings are already past SLA.
- Top recurring mapped CWEs are `CWE-1333` (`29`), `CWE-407` (`13`), `CWE-22` (`11`), `CWE-79` (`11`), and `CWE-20` (`6`). OWASP categories were not consistently populated by the imported parsers in this dataset.

Evidence: `labs/lab10/report/metrics-snapshot.md`, `labs/lab10/report/dojo-report.html`, `labs/lab10/report/findings.csv`.
