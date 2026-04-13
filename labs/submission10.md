# Lab 10 Submission — Vulnerability Management & Response with DefectDojo

**Student:** Sarmat  
**Date:** April 13, 2026

---

## Task 1 — DefectDojo Local Setup

DefectDojo was deployed locally using Docker Compose from the official repository.

**Setup steps:**
```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/setup/django-DefectDojo --depth 1
cd labs/lab10/setup/django-DefectDojo
docker compose build
docker compose up -d
```

**Running containers:**
- `django-defectdojo-nginx-1` — reverse proxy on port 8080
- `django-defectdojo-uwsgi-1` — Django application server
- `django-defectdojo-celeryworker-1` — async task worker
- `django-defectdojo-celerybeat-1` — scheduled tasks
- `django-defectdojo-postgres-1` — PostgreSQL database
- `django-defectdojo-valkey-1` — Redis-compatible cache

**Admin credentials** retrieved from initializer logs:
```
docker compose logs initializer | grep "Admin password:"
# Admin password: <printed once at first startup>
```

**Structure created via API:**
- Product Type: `Engineering`
- Product: `Juice Shop`
- Engagement: `Labs Security Testing` (ID: 1)

---

## Task 2 — Import Prior Findings

### Import Summary

| Tool | Scan Type | Findings Imported | Test ID |
|------|-----------|-------------------|---------|
| ZAP (unauthenticated) | ZAP Scan | 11 alerts | 9 |
| ZAP (authenticated) | ZAP Scan | 22 alerts | 10 |
| Semgrep | Semgrep JSON Report | 25 findings | 5 |
| Nuclei | Nuclei Scan | 16 findings | 6 |
| Trivy | — | Skipped (lab4 files not available) | — |
| Grype | — | Skipped (lab4 files not available) | — |

**Total active findings after import: 74**

### Import Notes

- ZAP JSON format is not supported by DefectDojo — converted to XML using a Python script before import
- Nuclei results were in JSONL format (one JSON object per line) — imported successfully with `Nuclei Scan` type
- Semgrep imported with `Semgrep JSON Report` type (not `Semgrep JSON` — that name is invalid in this version)
- Trivy/Grype files were not available from Lab 4 (not committed to the repo)

---

## Task 3 — Reporting & Program Metrics

### Metrics Snapshot

**Date:** April 13, 2026  
**Engagement:** Labs Security Testing — Juice Shop

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 9 |
| Medium | 32 |
| Low | 16 |
| Informational | 17 |
| **Total Active** | **74** |

**Findings per tool:**

| Tool | Findings |
|------|----------|
| ZAP Scan | 33 |
| Semgrep JSON Report | 25 |
| Nuclei Scan | 16 |

### Key Metrics Summary

- **74 active findings** across 3 tools — no findings have been mitigated or verified yet, representing the full raw import state
- **ZAP dominates by volume (33 findings)** covering runtime issues like missing security headers, CORS misconfiguration, and cross-domain JavaScript inclusion — these are deployment-level issues invisible to SAST
- **Semgrep found 25 code-level issues** including SQL injection patterns, hardcoded JWT secrets, and path traversal — these require developer remediation at the source code level
- **9 High severity findings** are the immediate priority — primarily SQL injection (Semgrep) and authentication/session issues (ZAP); no Critical findings were detected, suggesting the application has basic protections in place
- **No SLA breaches** at time of capture — all findings are newly imported with no due dates set; recommended SLA: Critical = 7 days, High = 30 days, Medium = 90 days

### Top Recurring Categories

Based on findings analysis:
1. **Injection (OWASP A03)** — SQL injection in search and login endpoints (Semgrep)
2. **Security Misconfiguration (OWASP A05)** — Missing CSP, CORS wildcard, deprecated headers (ZAP)
3. **Identification & Authentication Failures (OWASP A07)** — Hardcoded JWT secret (Semgrep)
4. **Vulnerable Components (OWASP A06)** — Outdated npm packages (Nuclei)
5. **Insecure Design (OWASP A04)** — Path traversal via file server (Semgrep)

### Artifacts

- `labs/lab10/report/metrics-snapshot.md` — severity/tool breakdown
- `labs/lab10/report/findings.csv` — full findings export (75 rows)
- `labs/lab10/imports/` — API responses for each import
