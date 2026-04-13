# Lab 10 — Vulnerability Management & Response with DefectDojo

## Task 1 — DefectDojo Local Setup

DefectDojo was deployed locally using Docker Compose from the upstream repository (`django-DefectDojo`). The stack includes nginx, uwsgi (Django), celerybeat, celeryworker, PostgreSQL 16, and Valkey (Redis-compatible cache). All six containers started successfully and the UI became accessible at `http://localhost:8080`. Admin credentials were extracted from the initializer logs.

**Containers running:**
- `django-defectdojo-nginx-1` — reverse proxy on ports 8080/8443
- `django-defectdojo-uwsgi-1` — Django application server
- `django-defectdojo-celerybeat-1` — periodic task scheduler
- `django-defectdojo-celeryworker-1` — async task worker
- `django-defectdojo-postgres-1` — database
- `django-defectdojo-valkey-1` — message broker/cache

**Structure created:**
- Product Type: **Engineering**
- Product: **Juice Shop**
- Engagement: **Labs Security Testing**

---

## Task 2 — Import Prior Findings

Findings from five scanning tools were imported into DefectDojo via the REST API (`/api/v2/import-scan/`) using the provided `run-imports.sh` script with `auto_create_context=true`. All scan results were generated against the running Juice Shop v19.0.0 instance (`bkimminich/juice-shop:v19.0.0`).

| Scanner             | Scan Type             | Source File                              | Findings Imported |
|---------------------|-----------------------|------------------------------------------|:-----------------:|
| ZAP                 | ZAP Scan              | `lab5/zap/zap-report-noauth.xml`         | 9                 |
| Semgrep             | Semgrep JSON Report   | `lab5/semgrep/semgrep-results.json`      | 39                |
| Trivy               | Trivy Scan            | `lab4/trivy/trivy-vuln-detailed.json`    | 194               |
| Nuclei              | Nuclei Scan           | `lab5/nuclei/nuclei-results.json`        | 10                |
| Grype               | Anchore Grype         | `lab4/syft/grype-vuln-results.json`      | 167               |
| **Total**           |                       |                                          | **457**           |

**Notes on tooling:**
- Semgrep (v1.99.0) was run directly against the Juice Shop source (extracted from the running container) with `--config auto`.
- Trivy (v0.69.3) scanned the container image with `--scanners vuln` producing detailed CVE output.
- Grype (v0.111.0) scanned the same image independently for SCA cross-validation.
- ZAP and Nuclei findings were generated from passive HTTP header analysis and endpoint probing of the live application.

Import responses are saved under `lab10/imports/`.

---

## Task 3 — Reporting & Program Metrics

### Severity Distribution (Open vs. Closed)

All 457 findings are currently **Active** (open). 194 Trivy findings were auto-verified on import. No findings have been closed or mitigated, as this represents the initial import baseline.

| Severity      | Open | Closed |
|---------------|:----:|:------:|
| Critical      | 24   | 0      |
| High          | 211  | 0      |
| Medium        | 150  | 0      |
| Low           | 45   | 0      |
| Informational | 27   | 0      |

### Findings per Tool

- **ZAP (DAST):** 9 findings — missing CSP/HSTS headers, CORS wildcard misconfiguration, deprecated Feature-Policy header, information disclosure via custom headers
- **Semgrep (SAST):** 39 findings — SQL injection via Sequelize string concatenation, eval() with user input, hardcoded JWT secrets, path traversal in file serving, prototype pollution patterns, MD5 usage, non-literal require()
- **Trivy (Container/SCA):** 194 findings — critical CVEs in zlib (CVE-2023-45853), OpenSSL (CVE-2024-6119, CVE-2024-4741), plus extensive npm dependency vulnerabilities across cross-spawn, ws, follow-redirects, cookie, braces, and many others
- **Nuclei (Misconfiguration):** 10 findings — exposed /ftp/ directory listing, /.git/ directory exposure, /encryptionkeys accessible without auth, /metrics and /api-docs publicly accessible, CORS wildcard, missing security headers
- **Grype (SCA):** 167 findings — independent SCA confirmation of Trivy results; flagged CVEs in both OS-level packages (Debian) and npm dependencies with severity ranging from Critical to Low

### SLA Status

- No SLA policies are currently configured in DefectDojo. Recommended thresholds:
  - Critical: 7 days
  - High: 30 days
  - Medium: 90 days
  - Low: 180 days
- Under these thresholds, 235 findings (Critical + High) would require triage within 30 days.
- No SLA breaches exist yet since all findings were freshly imported today (2026-04-13).

### Top Recurring CWE / OWASP Categories

- **CWE-1333 (ReDoS):** 35 findings — inefficient regular expression patterns in multiple npm packages vulnerable to denial-of-service via crafted input
- **CWE-22 (Path Traversal):** 18 findings — improper path validation in file serving routes and vulnerable dependency versions
- **CWE-400 (Resource Consumption):** 18 findings — uncontrolled resource usage in various npm packages
- **CWE-79 (XSS):** 13 findings — cross-site scripting via unescaped template output and reflected input
- **CWE-1321 (Prototype Pollution):** 10 findings — prototype pollution patterns in application code and dependencies
- **CWE-89 (SQL Injection):** 9 findings — SQL injection via string concatenation in Sequelize queries

### Key Metric Summary

- **Total findings across all tools:** 457 (24 Critical, 211 High, 150 Medium, 45 Low, 27 Info)
- **Dependency risk dominates:** Over 75% of findings (Trivy + Grype) originate from known CVEs in third-party npm packages and Debian OS packages — typical for Node.js applications with large dependency trees
- **Cross-tool validation:** Trivy and Grype independently flagged overlapping CVEs (e.g., cross-spawn CVE-2024-21538, ws CVE-2024-37890), confirming multi-scanner accuracy and demonstrating why SCA tool cross-validation is valuable
- **Exploitable application-level risks:** Semgrep identified 39 SAST findings including direct SQL injection, code injection via eval(), hardcoded secrets, and prototype pollution — these are directly exploitable in OWASP Juice Shop by design
- **Exposed sensitive endpoints:** Nuclei confirmed that /.git/, /encryptionkeys, /ftp/, /metrics, and /api-docs/ are all accessible without authentication, representing quick-win remediation targets

---

## Deliverables

- `labs/lab10/report/metrics-snapshot.md` — baseline severity counts and per-tool breakdown
- `labs/lab10/report/dojo-report.html` — stakeholder-ready HTML report with severity distribution, OWASP mapping, and recommendations
- `labs/lab10/report/findings.csv` — full findings list (457 rows) for spreadsheet analysis
- `labs/lab10/imports/run-imports.sh` — automated import script
