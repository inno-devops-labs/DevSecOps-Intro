# Lab 10 Submission — Vulnerability Management & Response with DefectDojo

## Task 1 — DefectDojo Local Setup

### 1.1 Clone and start

```bash
git clone --depth=1 https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/setup/django-DefectDojo
cd labs/lab10/setup/django-DefectDojo
docker compose pull
docker compose up -d
```

Containers running (`docker compose ps`):

| Service       | Image                              | Port           |
|---------------|------------------------------------|----------------|
| nginx         | defectdojo/defectdojo-nginx:latest | 0.0.0.0:8080   |
| uwsgi         | defectdojo/defectdojo-django:latest| —              |
| celeryworker  | defectdojo/defectdojo-django:latest| —              |
| celerybeat    | defectdojo/defectdojo-django:latest| —              |
| postgres      | postgres:18.3-alpine               | 5432 (internal)|
| valkey        | valkey:9.0.3-alpine                | 6379 (internal)|

UI accessible at `http://localhost:8080`.

### 1.2 Admin credentials

```bash
docker compose logs initializer | grep "Admin password:"
# Admin password: 5qvSdc1pMvdvUVhyCTuVh7
```

API token obtained via:
```bash
curl -s -X POST http://localhost:8080/api/v2/api-token-auth/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"5qvSdc1pMvdvUVhyCTuVh7"}'
# → token: fd0a540054759273f80e8ffdca8d91e9fa25e62f
```

Product Type **Engineering**, Product **Juice Shop**, and Engagement **Labs Security Testing** created via auto-create.

---

## Task 2 — Import Prior Findings

### Scan reports generated (prior labs)

| Tool    | Path                                         | Findings |
|---------|----------------------------------------------|----------|
| Trivy   | `labs/lab4/trivy/trivy-vuln-detailed.json`   | 194 vulns (11C/102H/62M/23L) |
| Grype   | `labs/lab4/syft/grype-vuln-results.json`     | 167 vulns (11C/88H/46M/8L/14I) |
| Semgrep | `labs/lab5/semgrep/semgrep-results.json`     | 40 findings (11H/26M/2L) |
| ZAP     | `labs/lab5/zap/zap-report-noauth.xml`        | 12 alerts (2M/6L/4I) |
| Nuclei  | `labs/lab5/nuclei/nuclei-results.json`       | 0 (no template matches) |

> **ZAP note:** DefectDojo's `ZAP Scan` importer requires XML format. The baseline scan was re-run with `-x` flag to produce `zap-report-noauth.xml`.

### Import execution

```bash
export DD_API="http://localhost:8080/api/v2"
export DD_TOKEN="fd0a540054759273f80e8ffdca8d91e9fa25e62f"
export DD_PRODUCT_TYPE="Engineering"
export DD_PRODUCT="Juice Shop"
export DD_ENGAGEMENT="Labs Security Testing"
bash labs/lab10/imports/run-imports.sh
```

Import results (from API responses saved under `labs/lab10/imports/`):

| Tool    | scan_type           | test_id | Imported |
|---------|---------------------|---------|----------|
| Semgrep | Semgrep JSON Report | 2       | 39       |
| Trivy   | Trivy Scan          | 3       | 198      |
| Nuclei  | Nuclei Scan         | 4       | 0        |
| Grype   | Anchore Grype       | 5       | 167      |
| ZAP     | ZAP Scan (XML)      | 6       | 12       |

---

## Task 3 — Reporting & Program Metrics

### Metrics summary (snapshot date: 2026-04-13)

- **Total active findings: 416** across 4 tools (Trivy, Grype, Semgrep, ZAP).
  - Critical: 22 | High: 201 | Medium: 136 | Low: 39 | Info: 18

- **Severity concentration at High (48%):** Most findings are npm dependency
  vulnerabilities in `juice-shop/node_modules` — 158 Node.js CVEs from Trivy and
  88 from Grype. Critical findings (22) include known RCE/prototype-pollution CVEs
  (e.g. CVE-2022-25883, lodash prototype-pollution).

- **Top CWE categories reveal recurring patterns:**
  - CWE-1333 ReDoS (34 findings) — regex complexity in npm deps, potential DoS vector.
  - CWE-22 Path Traversal (17) + CWE-89 SQL Injection (7) — direct OWASP Top 10 risks
    confirmed by both Semgrep SAST and tool-independent CVEs.
  - CWE-79 XSS (11) — corroborated by Semgrep findings in frontend JS.

- **Tool overlap / deduplication:** Trivy and Grype share the same npm advisory
  database, so 150+ findings are duplicated across test_id=3 and test_id=5.
  Enabling DefectDojo's hash-based deduplication algorithm on re-import would
  collapse these into ~60 unique CVEs, giving a cleaner risk picture.

- **SLA outlook (no SLA breaches):** Engagement target end is 2026-05-13 (30 days).
  No findings have been manually set with due dates. With 22 Critical findings,
  recommended SLA policy would be: Critical ≤ 7 days, High ≤ 30 days — applying
  this retroactively would flag all 22 Critical items as requiring action by 2026-04-20.

### Artifacts

| Artifact                               | Location                                  |
|----------------------------------------|-------------------------------------------|
| Metrics snapshot                       | `labs/lab10/report/metrics-snapshot.md`  |
| HTML security report                   | `labs/lab10/report/dojo-report.html`     |
| Findings CSV (416 rows)                | `labs/lab10/report/findings.csv`         |
| Import API responses                   | `labs/lab10/imports/*-response.json`     |

---

## Checklist

- [x] Task 1 — Dojo setup and structure
- [x] Task 2 — Imports completed (multi-tool: ZAP, Semgrep, Trivy, Nuclei, Grype)
- [x] Task 3 — Report + metrics package
