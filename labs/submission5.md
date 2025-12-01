# Lab 5 — SAST & DAST (OWASP Juice Shop)

## Task 1 — SAST (Semgrep)
- Scan target: `bkimminich/juice-shop:v19.0.0` source code; reports in `labs/lab5/semgrep/semgrep-results.json` (machine) and `labs/lab5/semgrep/semgrep-report.txt` (text).
- Findings: **95 total** (ERROR 21 / WARNING 45 / INFO 29).
- Five most critical:
  1) Hardcoded OAuth URL/secret — `config/default.yml:59` (rules.generic.secrets.security.detected-google-oauth-url, ERROR)  
  2) Tainted Sequelize query (SQLi risk) — `data/static/codefixes/dbSchemaChallenge_1.ts:5` (express-sequelize-injection, ERROR)  
  3) Manually concatenated SQL string — `data/static/codefixes/dbSchemaChallenge_1.ts:5` (tainted-sql-string, ERROR)  
  4) Tainted Sequelize query (SQLi risk) — `data/static/codefixes/unionSqlInjectionChallenge_1.ts:6` (express-sequelize-injection, ERROR)  
  5) Tainted Sequelize query (SQLi risk) — `data/static/codefixes/unionSqlInjectionChallenge_3.ts:10` (express-sequelize-injection, ERROR)

## Task 2 — DAST (multi-tool)
### ZAP: unauth vs auth
- Alerts: unauth **12** (`labs/lab5/zap/zap-report-noauth.json`), auth **11** (`labs/lab5/zap/zap-report-auth.json`).
- Auth scan covers session-protected surface (`/rest/*`), exposing issues like CSP missing, Session ID in URL rewrite, cross-domain misconfiguration on authenticated flows.
- Why auth matters: without login only public pages are tested; with login we see session handling, private APIs, and admin/user features that change risk priority.

### Tool comparison
| Tool        | Findings | Severity breakdown                 | Best use case |
|-------------|----------|------------------------------------|---------------|
| ZAP (auth)  | 11       | Medium 4 / Low 4 / Info 3          | Full web scan with session: headers, session mgmt, client issues |
| Nuclei      | 24       | Mostly info templates (swagger, host-header) | Fast known-exposure/CVE template sweep |
| Nikto       | 84       | Primarily Low/Info (headers, backups) | Web server misconfig/backup path checks |
| SQLmap      | 2        | 1 exploitable (`/rest/products/search`), 1 tested login non-injectable | Deep SQLi confirmation and DB dump |

### Sample findings
- ZAP: CSP Header Not Set; Session ID in URL Rewrite; Cross-Domain Misconfiguration on `http://localhost:3000`.
- Nuclei: public Swagger at `/api-docs/swagger.yaml`; host-header interaction; DNS rebinding template hit.
- Nikto: missing HSTS/Referrer/Permissions/CSP; many potential backup/cert files (`*.tar`, `*.jks`, `*.cer`); uncommon header `x-recruiting`.
- SQLmap: SQLi on `GET /rest/products/search?q=*` (SQLite, boolean-based blind) with dumps under `labs/lab5/sqlmap/localhost/dump/SQLite_masterdb/`; login endpoint not injectable with tested techniques.

## Task 3 — SAST/DAST correlation
- Counts: SAST **95** vs combined DAST **121** (ZAP 11 + Nuclei 24 + Nikto 84 + SQLmap 2).
- SAST-only: hardcoded secrets (`config/default.yml`), tainted SQL construction in TS, potential secrets in `data/static/users.yml`.
- DAST-only: missing security headers (CSP/HSTS/Referrer), exposed Swagger, runtime-confirmed SQLi, host-header interaction, backup artifacts on the server.
- Rationale: SAST catches code patterns/secrets pre-deploy; DAST reveals runtime config, reachable attack surface, and exploitability. Both are required for full coverage across CI and deployed environments.

## Recommendations
- Fix SQLi: replace manual SQL concatenation with parameterized queries in `data/static/codefixes/*`.
- Remove secrets from repo (`config/default.yml`, `data/static/users.yml`); load from env/secret store.
- Enable security headers (CSP, HSTS, Referrer-Policy, Permissions-Policy) and remove Session IDs from URLs.
- Restrict/disable public Swagger and host-header acceptance; block/clean backup file paths.
- Automate: Semgrep + ZAP (auth) in CI; Nuclei/Nikto as quick smoke checks; SQLmap targeted on suspected endpoints.
