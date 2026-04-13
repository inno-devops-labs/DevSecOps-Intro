# Lab 10 Submission - Vulnerability Management & Response with DefectDojo

## Student / Context
- Name: `Danil Fishchenko`
- Target branch for PR: `feature/lab10`
- Work date: `2026-04-13`
- Repository root: `DevSecOps-Intro/`
- Platform used: local OWASP DefectDojo via Docker Compose on `http://localhost:8080`
- Target product hierarchy:
  - Product Type: `Engineering`
  - Product: `Juice Shop`
  - Engagement: `Labs Security Testing`

Captured engagement state on `2026-04-13` from the exported findings/report artifacts:
- `1` product
- `1` engagement
- `5` tests
- `400` findings

## Task 1 - DefectDojo Local Setup

Setup evidence saved under `labs/lab10/setup/`:
- `compose-check.txt` shows the local Docker Compose version is supported.
- `docker-compose-ps.txt` shows the full DefectDojo stack running locally:
  - `nginx`
  - `uwsgi`
  - `celerybeat`
  - `celeryworker`
  - `postgres`
  - `valkey`

Operational notes:
- The DefectDojo UI was exposed at `http://localhost:8080`.
- Admin-level authenticated API access was successfully used for imports, which confirms that the admin account was initialized correctly and could be used to operate the instance.
- I did not store the admin password or API token in the repository.

## Task 2 - Multi-Tool Findings Import

Importer helper:
- `labs/lab10/imports/run-imports.sh`

Important implementation detail:
- The current DefectDojo `ZAP Scan` parser expects XML input, so the importer intentionally prefers `labs/lab5/zap/zap-report-noauth.xml` when the detected scan type is `ZAP Scan`, even though the lab also keeps a JSON export.
- The importer script is configured to target `/api/v2/reimport-scan/` for future idempotent reruns, so repeated executions update the latest matching test instead of creating duplicate tests on every execution.

Per-tool import results:

| Tool | Source report | DefectDojo scan type | Findings |
| --- | --- | --- | ---: |
| ZAP | `labs/lab5/zap/zap-report-noauth.xml` | `ZAP Scan` | `12` |
| Semgrep | `labs/lab5/semgrep/semgrep-results.json` | `Semgrep JSON Report` | `25` |
| Trivy | `labs/lab4/trivy/trivy-vuln-detailed.json` | `Trivy Scan` | `194` |
| Nuclei | `labs/lab5/nuclei/nuclei-results.json` | `Nuclei Scan` | `2` |
| Grype | `labs/lab4/syft/grype-vuln-results.json` | `Anchore Grype` | `167` |

Saved API evidence:
- `labs/lab10/imports/import-zap-report-noauth.xml.json`
- `labs/lab10/imports/import-semgrep-results.json.json`
- `labs/lab10/imports/import-trivy-vuln-detailed.json.json`
- `labs/lab10/imports/import-nuclei-results.json.json`
- `labs/lab10/imports/import-grype-vuln-results.json.json`

Import interpretation:
- All five required tool families were loaded into the same engagement.
- The imported dataset spans DAST (`ZAP`, `Nuclei`), SAST (`Semgrep`), and SCA / package vulnerability scanning (`Trivy`, `Grype`).
- `194` findings are marked `Verified`; these come from the Trivy import and materially affect prioritization because they are already validated by the parser/tool mapping.

## Task 3 - Reporting And Metrics Package

Generated artifacts:
- `labs/lab10/report/metrics-snapshot.md`
- `labs/lab10/report/dojo-report.html`
- `labs/lab10/report/findings.csv`
- `labs/lab10/report/lab10-metrics.json`

Metric summary bullets required by the lab:
- The baseline snapshot contains `400` open findings and `0` closed findings: `22` Critical, `195` High, `126` Medium, `37` Low, and `20` Informational.
- The current state is a pre-remediation baseline: `194` findings are already marked `Verified`, but `0` findings are `Mitigated`, so no closure work has started yet.
- SCA-heavy tooling dominates the exposure volume: `Trivy (194)` plus `Grype (167)` account for `361 / 400` findings, so vulnerable and outdated components are the primary risk driver in this dataset.
- SLA outlook is currently manageable on `2026-04-13`: there are `0` overdue findings, but all `22` Critical findings reach their SLA date on `2026-04-20`; High findings begin expiring on `2026-05-13`.
- The most common recurring non-zero CWE categories are `CWE-1333 (32)`, `CWE-400 (17)`, `CWE-22 (17)`, `CWE-79 (13)`, and `CWE-407 (13)`. Inference from the tool mix and CWE distribution: the dominant OWASP-aligned theme is `A06: Vulnerable and Outdated Components`, with additional recurring web risk patterns in XSS and path traversal classes.

## Artifact Index

- Setup:
  - `labs/lab10/setup/compose-check.txt`
  - `labs/lab10/setup/docker-compose-ps.txt`
- Imports:
  - `labs/lab10/imports/run-imports.sh`
  - `labs/lab10/imports/*.json`
- Reports:
  - `labs/lab10/report/metrics-snapshot.md`
  - `labs/lab10/report/dojo-report.html`
  - `labs/lab10/report/findings.csv`
  - `labs/lab10/report/lab10-metrics.json`

## Final Acceptance Check

- [x] DefectDojo runs locally and an admin user can log in
- [x] Product Type, Product, and Engagement are configured
- [x] Imports completed for ZAP, Semgrep, Trivy, Nuclei, and Grype
- [x] Reporting artifacts generated under `labs/lab10/`
- [x] Summary bullets added to `labs/submission10.md`
