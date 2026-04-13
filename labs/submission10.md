# Lab 10 Submission — Vulnerability Management & Response With DefectDojo

**Environment:** macOS host with Docker `28.5.2`, Docker Compose `v2.40.3`, `jq 1.7.1`, `curl 8.7.1`  
**DefectDojo source:** `labs/lab10/setup/django-DefectDojo` (upstream `dev` branch)  
**DefectDojo access URL used:** `http://localhost:18080`  
**Date completed:** 2026-04-13

This report documents the work I completed locally for Lab 10 without making any git commits. All generated artifacts were saved under `labs/lab10/`, and the final submission artifacts are linked below.

## Task 1 — DefectDojo Local Setup

### What I did

I created the lab directories and cloned DefectDojo into:

- `labs/lab10/setup/django-DefectDojo`

Then I started the platform with Docker Compose. In this environment, host port `8080` was already occupied by another local process, so I ran DefectDojo on `18080` instead:

```bash
docker compose down
DD_PORT=18080 DD_TLS_PORT=18443 docker compose up -d
```

The stack started successfully with `postgres`, `valkey`, `initializer`, `uwsgi`, `celerybeat`, `celeryworker`, and `nginx`. Setup evidence was saved to:

- `labs/lab10/setup/docker-compose-ps.txt`
- `labs/lab10/setup/initializer.log`
- `labs/lab10/setup/access-notes.txt`

### Local setup notes

- The initializer reported `Admin user already exists; skipping first-boot setup`, so I reset the local admin password non-interactively to continue automation.
- I generated an API token locally for the `admin` account and used it for all imports and metrics collection.
- No git history was changed during this lab.

## Task 2 — Import Prior Findings

### Import workflow

I used the provided importer script:

- `labs/lab10/imports/run-imports.sh`

I made two small portability fixes so the script works in this macOS environment:

1. Replaced `mapfile` with a Bash 3-compatible loop.
2. Added automatic conversion of the provided ZAP JSON report into ZAP XML, because the current DefectDojo `ZAP Scan` importer accepts XML only.

The converted XML file and successful ZAP import response are saved in:

- `labs/lab10/imports/zap-report-noauth.xml`
- `labs/lab10/imports/import-zap-report-noauth.xml.json`

### Import results

Imported reports:

- ZAP: 12 findings
- Semgrep: 25 findings
- Trivy: 147 findings
- Grype: 122 findings

Skipped report:

- Nuclei: source file not present at `labs/lab5/nuclei/nuclei-results.json`, so the importer skipped it cleanly
- Evidence: `labs/lab10/imports/nuclei-status.txt`

Saved import responses:

- `labs/lab10/imports/import-semgrep-results.json.json`
- `labs/lab10/imports/import-trivy-vuln-detailed.json.json`
- `labs/lab10/imports/import-grype-vuln-results.json.json`
- `labs/lab10/imports/import-zap-report-noauth.xml.json`

Total findings imported into the engagement:

- `306`

## Task 3 — Reporting & Program Metrics

### Exported artifacts

I authenticated to the DefectDojo web UI with `curl` session cookies and exported the engagement report plus the findings CSV directly from DefectDojo:

- `labs/lab10/report/dojo-report.html`
- `labs/lab10/report/findings.csv`
- `labs/lab10/report/metrics-snapshot.md`
- `labs/lab10/report/metrics-summary.json`

The final HTML report was regenerated through DefectDojo's normal report generation flow with executive summary and table of contents enabled, so the saved artifact is closer to the intended governance-style output from the UI.

### Metrics summary

- The engagement baseline on **2026-04-13** contained **306 open findings** and **0 closed findings**. Severity mix was **21 Critical**, **154 High**, **88 Medium**, **27 Low**, and **16 Informational**.
- Tool distribution was dominated by software composition analysis: **Trivy 147**, **Grype 122**, **Semgrep 25**, and **ZAP 12**. Trivy and Grype together account for **269/306 findings (87.9%)**.
- **143 findings were verified** and **0 findings were mitigated**, so the verified backlog is non-trivial but remediation has not yet started in DefectDojo.
- SLA outlook is immediate for the critical backlog: **21 Critical findings are due within 14 days**, all with SLA dates on **2026-04-20**. There were **no overdue findings** as of **2026-04-13**.
- Top recurring CWE values were **CWE-1333 (29)**, **CWE-407 (13)**, **CWE-22 (11)**, **CWE-79 (11)**, and **CWE-89 (6)**. From these findings and the import mix, the dominant OWASP themes are best understood as **A06 Vulnerable and Outdated Components** plus **A03 Injection** and some **A05 Security Misconfiguration** findings.

## Deliverables

- Setup evidence: `labs/lab10/setup/docker-compose-ps.txt`, `labs/lab10/setup/initializer.log`, `labs/lab10/setup/access-notes.txt`
- Import artifacts: `labs/lab10/imports/`
- Reports: `labs/lab10/report/dojo-report.html`, `labs/lab10/report/findings.csv`, `labs/lab10/report/metrics-snapshot.md`

## Final checklist

- [x] Task 1 — Dojo setup and structure
- [x] Task 2 — Imports completed (ZAP, Semgrep, Trivy, Grype; Nuclei skipped because source report was absent)
- [x] Task 3 — Report + metrics package
- [x] No git commits created
