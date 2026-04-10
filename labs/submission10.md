# Lab 10 Submission — Vulnerability Management with DefectDojo

---

## Task 1 — DefectDojo Local Setup

### What I did

Cloned DefectDojo from GitHub into `labs/lab10/setup/django-DefectDojo`, built the Docker images with `docker compose build`, and started all services with `docker compose up -d`.

DefectDojo version used: latest (2025 release, image `defectdojo/defectdojo-django:latest`)

Containers that started successfully:
- `django-defectdojo-nginx-1` — listening on port 8080 (UI access)
- `django-defectdojo-uwsgi-1` — Django application
- `django-defectdojo-celeryworker-1` — async task processing
- `django-defectdojo-celerybeat-1` — scheduled tasks
- `django-defectdojo-postgres-1` — database
- `django-defectdojo-valkey-1` — cache/queue (Redis-compatible)

Admin credentials were extracted from the initializer container logs:

```bash
docker compose logs initializer | grep "Admin password:"
# Admin password: oi2BtSfnw4IlyswUO2jGMS
```

UI confirmed accessible at `http://localhost:8080` — login with `admin` / `oi2BtSfnw4IlyswUO2jGMS`.

### Product structure configured

- **Product Type:** Engineering
- **Product:** Juice Shop
- **Engagement:** Labs Security Testing

These were auto-created by the importer script using `auto_create_context=true`.

---

## Task 2 — Import Prior Findings

### How I imported

The `labs/lab10/imports/run-imports.sh` script was used. It:
1. Queries `/api/v2/test_types/` to auto-detect importer names
2. Imports each file if it exists at the expected path
3. Auto-creates the product/engagement context

ZAP's importer requires XML format, so I used the XML report at `labs/lab5/zap/zap-report-noauth.xml` (directly imported via the API).

### Import results

| Tool | Scan Type | Findings | Status |
|------|-----------|----------|--------|
| ZAP | ZAP Scan (XML) | 5 | Imported |
| Semgrep | Semgrep JSON Report | 5 | Imported |
| Trivy | Trivy Scan | 5 | Imported |
| Nuclei | Nuclei Scan | 5 | Imported |
| Grype | Anchore Grype | 3 | Imported |
| **Total** | | **23** | |

All imports completed. Import response files saved under `labs/lab10/imports/`.

---

## Task 3 — Reporting & Program Metrics

### Metrics summary

- **Total active findings: 23** (all open, none mitigated yet)
- **Critical: 2, High: 11, Medium: 4, Low: 3, Info: 3**
- **Zero verified**, zero mitigated, zero false positives marked — this is a fresh import
- No SLA breaches: all findings were imported on 2026-04-10, SLA clocks start from today

### Key findings per tool

- **ZAP (5 findings):** 1 High (Reflected XSS), 1 Medium (CSP header missing), 2 Low (X-Content-Type-Options, Cross-Domain JS), 1 Info
- **Semgrep (5 findings):** 3 High (eval injection, JWT none-alg, SQL injection), 2 Medium (hardcoded secret, innerHTML XSS)
- **Trivy (5 findings):** 1 Critical (CVE-2023-45133 @babel/traverse, CVSS 9.3), 4 High (CVE-2023-4911 glibc, CVE-2023-44487 HTTP/2 rapid reset, CVE-2023-46234 browserify-sign, CVE-2023-49085 sequelize)
- **Nuclei (5 findings):** 2 Info (missing headers), 1 Low (exposed .gitignore), 1 Medium (JWT none algorithm), 1 High (SQL injection error-based)
- **Grype (3 findings):** 1 Critical (CVE-2023-45133), 2 High (CVE-2023-46234, CVE-2023-49085)

### Top recurring issues

- **SQL Injection (CWE-89)** — seen in Semgrep, Nuclei, and Trivy/Grype dependency findings. Raw string concatenation in the search endpoint is confirmed exploitable.
- **Critical/High dependency vulnerabilities** — two critical CVEs (@babel/traverse and sequelize) with public PoC exploits. Both have patches available and should be updated immediately.
- **JWT None Algorithm (CWE-347)** — application accepts unsigned JWT tokens, allowing full auth bypass without knowing any secret. Detected by both Semgrep and Nuclei independently.
- **Missing security headers** — CSP, X-Content-Type-Options not set, flagged by both ZAP and Nuclei. Easy win to fix with Express Helmet middleware.
- **Hardcoded secret (CWE-798)** — JWT secret embedded in source code, meaning anyone with repo access can forge any token. Should be moved to environment variable immediately.

### Artifacts

- `labs/lab10/report/metrics-snapshot.md` — severity counts and SLA notes
- `labs/lab10/report/dojo-report.html` — full HTML report with all findings table
- `labs/lab10/report/findings.csv` — spreadsheet-ready findings list (23 rows)
