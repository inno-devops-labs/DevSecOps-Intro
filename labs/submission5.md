# Lab 5 - Security Analysis (SAST + DAST)

## Scope
- Target application: `bkimminich/juice-shop:v19.0.0`
- SAST tool: `Semgrep`
- DAST tools: `ZAP`, `Nuclei`, `Nikto`, `SQLmap`

## Task 1 - Static Application Security Testing (Semgrep)

### Artifacts
- `labs/lab5/semgrep/semgrep-results.json`
- `labs/lab5/semgrep/semgrep-report.txt`
- `labs/lab5/analysis/sast-analysis.txt`

### SAST Tool Effectiveness
- Files scanned: `1014`
- Findings: `25`
- Files with findings: `20`
- Severity split: `7 ERROR`, `18 WARNING`
- Main vulnerability classes found:
  - SQL injection sinks in Sequelize queries
  - Dangerous code execution (`eval`)
  - Path traversal risk via `res.sendFile`
  - Open redirect patterns
  - Hardcoded JWT secret
  - Potential XSS patterns (raw HTML/script usage)

### Top 5 Critical Semgrep Findings
| Vulnerability Type | File | Line | Severity |
|---|---|---:|---|
| SQL Injection (Sequelize tainted query) | `src/routes/search.ts` | 23 | ERROR |
| SQL Injection (Sequelize tainted query) | `src/routes/login.ts` | 34 | ERROR |
| Code Injection (`eval` data flow from request) | `src/routes/userProfile.ts` | 62 | ERROR |
| Path Traversal (`res.sendFile` with user input) | `src/routes/fileServer.ts` | 33 | WARNING |
| Hardcoded JWT Secret | `src/lib/insecurity.ts` | 56 | WARNING |

## Task 2 - Dynamic Application Security Testing (Multi-Tool)

### Artifacts
- ZAP:
  - `labs/lab5/zap/report-noauth.html`
  - `labs/lab5/zap/zap-report-noauth.json`
  - `labs/lab5/zap/report-auth.html`
  - `labs/lab5/zap/zap-report-auth.json`
  - `labs/lab5/zap/zap-noauth-scan.log`
  - `labs/lab5/zap/zap-auth-scan.log`
- Nuclei:
  - `labs/lab5/nuclei/nuclei-results.json`
- Nikto:
  - `labs/lab5/nikto/nikto-results.txt`
- SQLmap:
  - `labs/lab5/sqlmap/results-03042026_0623am.csv`
  - `labs/lab5/sqlmap/sqlmap-search.log`
  - `labs/lab5/sqlmap/sqlmap-login.log`
- Analysis:
  - `labs/lab5/analysis/zap-comparison.txt`
  - `labs/lab5/analysis/dast-summary.txt`

### Authenticated vs Unauthenticated ZAP Scanning
- Unauthenticated baseline discovered: `95` URLs
- Authenticated spider discovered: `145` URLs
- Authenticated AJAX spider discovered: `352` URLs
- Authenticated combined discovery: `497` URLs
- Relative increase vs baseline: `423%`

Authenticated-only endpoint examples:
- `http://localhost:3000/rest/admin/application-configuration`

Why authenticated scanning matters:
- It expands attack surface to privileged/user flows that are not visible to anonymous scans.
- It reveals risks in authenticated business logic and admin APIs.

### Tool Comparison Matrix
| Tool | Findings | Severity Breakdown | Best Use Case |
|---|---:|---|---|
| ZAP (authenticated) | 14 alerts | High: 1, Medium: 5, Low: 4, Info: 4 | Broad web app testing with crawling + active checks, including authenticated paths |
| Nuclei | 2 matches | Info: 2 | Fast detection of known exposures/templates (e.g., public Swagger endpoint) |
| Nikto | 82 issues | Not severity-scored in report (mostly misconfig/exposure style findings) | Quick server/header/configuration checks |
| SQLmap | 2 confirmed SQLi points | Boolean-based blind SQLi in both tested endpoints | Deep, targeted SQL injection validation and exploitation |

### Tool-Specific Strengths and Example Findings
- ZAP:
  - Strength: full crawler + active scan with auth support.
  - Example findings: `SQL Injection`, `Missing Anti-clickjacking Header`, `Content Security Policy (CSP) Header Not Set`.
- Nuclei:
  - Strength: speed and known-template matching.
  - Example findings: `Public Swagger API - Detect` on `/api-docs/swagger.json`, `X-Recruiting Header`.
- Nikto:
  - Strength: server hardening/misconfiguration visibility.
  - Example findings: missing `X-XSS-Protection`, accessible `/ftp/` path from `robots.txt`, many potential backup/cert-like paths.
- SQLmap:
  - Strength: exploit confirmation for SQLi.
  - Example findings: SQLi in `/rest/products/search?q=*` and `/rest/user/login` JSON `email` parameter, backend identified as SQLite.

## Task 3 - SAST/DAST Correlation and Security Assessment

### Findings Comparison
- SAST findings (Semgrep): `25`
- Combined DAST findings (ZAP + Nuclei + Nikto + SQLmap raw sum): `100`

### Correlation
- Overlap (found by both approaches):
  - SQL injection risk in login/search paths:
    - SAST flagged tainted Sequelize usage (`src/routes/login.ts`, `src/routes/search.ts`).
    - DAST confirmed runtime SQLi (`ZAP SQL Injection` + `SQLmap` confirmed two injection points).

### Vulnerability Types Found Only by SAST
- Hardcoded secret in source code (`jwt` secret value).
- Dangerous `eval` request-data flow.
- Template/code-level insecure patterns that may not be externally reachable in one runtime scan.

### Vulnerability Types Found Only by DAST
- Missing runtime security headers (CSP, anti-clickjacking, transport/header issues).
- Publicly exposed runtime assets/endpoints (e.g., swagger docs endpoint, admin endpoint visibility with auth).
- Server-level behavior/misconfiguration findings from HTTP response behavior.

### Why SAST and DAST Differ
- SAST inspects code paths and insecure patterns before execution.
- DAST validates real runtime behavior, deployed configuration, and externally reachable attack surface.

### Recommendations
1. Keep Semgrep in PR/CI for early code-level blocking (`ERROR` as fail gate).
2. Run authenticated ZAP regularly in staging to cover privileged routes.
3. Use SQLmap only as targeted follow-up when SAST/ZAP indicate SQLi.
4. Use Nuclei + Nikto as fast supplemental checks for exposure/misconfiguration drift.

## Notes
- The image names in the lab text for Nikto/SQLmap were outdated in this environment:
  - Used `alpine/nikto` instead of `sullo/nikto`.
  - Used `googlesky/sqlmap` instead of `sqlmapproject/sqlmap`.
