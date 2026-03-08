# Lab 5 — Security Analysis: SAST & DAST of OWASP Juice Shop

**Target:** `bkimminich/juice-shop:v19.0.0`  
**Date:** March 8, 2026

## Task 1 — SAST with Semgrep

### SAST Tool Effectiveness
- Tool: `semgrep/semgrep:latest` with `p/security-audit` + `p/owasp-top-ten`.
- Findings: **25** total (`ERROR: 7`, `WARNING: 18`).
- Files scanned: **847** (`labs/lab5/semgrep/semgrep-results.json`).
- Coverage quality: broad TypeScript/JavaScript coverage, with direct detection of:
  - SQL injection patterns in Sequelize queries
  - Dangerous dynamic code execution (`eval`)
  - Hardcoded secrets
  - Path traversal/file disclosure patterns
  - Open redirect patterns

### Critical Vulnerability Analysis (Top 5)

Severity mapping used: `ERROR -> High`, `WARNING -> Medium`.

| # | Vulnerability Type | File:Line | Semgrep Severity |
|---|---|---|---|
| 1 | Code Injection / RCE risk (`eval` with request data) | `/src/routes/userProfile.ts:62` | ERROR (High) |
| 2 | SQL Injection (tainted input into Sequelize) | `/src/routes/login.ts:34` | ERROR (High) |
| 3 | SQL Injection (tainted input into Sequelize) | `/src/routes/search.ts:23` | ERROR (High) |
| 4 | Hardcoded JWT Secret / Credential Exposure | `/src/lib/insecurity.ts:56` | WARNING (Medium) |
| 5 | Path Traversal / Arbitrary File Read via `sendFile` | `/src/routes/fileServer.ts:33` | WARNING (Medium) |

## Task 2 — DAST with Multiple Tools

### Authenticated vs Unauthenticated Scanning (ZAP)

Source: `labs/lab5/analysis/zap-comparison.txt`

- Unauthenticated scan:
  - Total alerts: **12**
  - Unique URLs with findings: **16**
- Authenticated scan:
  - Total alerts: **8**
  - Unique URLs with findings: **10**

Authenticated endpoints discovered in authenticated run:
- `http://localhost:3000/rest/user`
- `http://localhost:3000/rest/user/login`

Why authenticated scanning matters:
- It tests session-aware behavior and routes not visible in purely public browsing.
- It validates auth/session flows (login and stateful behavior), which unauth scans cannot verify deeply.
- It is required to reveal user-context attack paths (authorization, session handling, identity endpoints).

Note on execution profile: to keep host resource usage stable, authenticated ZAP used a bounded profile (`spider + passive + short active`) without long AJAX crawling.

### Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|---|---:|---|---|
| ZAP (authenticated) | 8 alert types | Medium: 2, Low: 3, Info: 3 | Broad web-app runtime assessment, auth/session testing |
| Nuclei | 1 | Medium: 1 | Fast template-based checks and repeatable policy checks |
| Nikto | 82 | Mixed server/misconfiguration style findings (no native severity tiers) | Web server hardening and exposed path/header checks |
| SQLmap | 2 injection points | SQLi confirmed on 2 parameters (high impact) | Deep SQL injection verification and DBMS fingerprinting |

### Tool-Specific Strengths with Examples

- **ZAP**
  - Strengths: end-to-end web scanning, authentication workflow support, structured HTML/JSON reports.
  - Example findings:
    - `Content Security Policy (CSP) Header Not Set`
    - `Cross-Domain Misconfiguration`

- **Nuclei**
  - Strengths: lightweight, template-driven checks for fast recurring scans.
  - Example finding:
    - `Missing Security Headers` (medium)

- **Nikto**
  - Strengths: server misconfiguration and exposed resource probing.
  - Example findings:
    - Missing `X-XSS-Protection` header
    - `/ftp/` exposed via `robots.txt` and additional interesting paths

- **SQLmap**
  - Strengths: confirms exploitability of SQL injection and identifies DBMS.
  - Example findings:
    - `/rest/products/search?q=*` injectable (boolean-based blind)
    - `/rest/user/login` JSON `email` parameter injectable (boolean-based blind)
    - Back-end DBMS fingerprint: `SQLite`

## Task 3 — SAST/DAST Correlation and Security Assessment

### SAST vs DAST Comparison

- SAST findings: **25**
- Combined DAST findings: **93** (`ZAP 8 + Nuclei 1 + Nikto 82 + SQLmap 2`)

Vulnerability types found **only by SAST**:
- Hardcoded credential/secret in source (`jwt-hardcode`)
- Dangerous code execution sink (`eval` data flow)
- Unquoted template-variable sink patterns in frontend templates

Vulnerability types found **only by DAST**:
- Runtime HTTP header misconfiguration (CSP/XSS/security header gaps)
- Runtime cache/cross-origin behavior findings
- Live SQL injection exploit confirmation against running endpoints

Why they differ:
- SAST inspects source logic and taint flows without executing the app.
- DAST validates actual runtime behavior, responses, deployment headers, and exploitability.
- Together they reduce blind spots: SAST finds latent code defects early; DAST proves what is reachable/exploitable at runtime.

### Security Recommendations

1. Replace raw/dynamic SQL patterns with strict parameterized query usage in login/search code paths.
2. Remove hardcoded secrets from source and load secrets through environment variables or a secret manager.
3. Eliminate request-influenced `eval` usage in `/src/routes/userProfile.ts`.
4. Harden file-serving routes (`sendFile`) with strict path allowlisting and canonical path validation.
5. Add/strengthen security headers (`Content-Security-Policy`, transport and cross-origin hardening headers).
6. Integrate Semgrep + ZAP + Nuclei + Nikto + SQLmap checks into CI/CD with guardrail thresholds for regression prevention.

## Evidence Files

- SAST:
  - `labs/lab5/semgrep/semgrep-results.json`
  - `labs/lab5/semgrep/semgrep-report.txt`
  - `labs/lab5/analysis/sast-analysis.txt`
- DAST:
  - `labs/lab5/zap/zap-report-noauth.json`
  - `labs/lab5/zap/zap-report-auth.json`
  - `labs/lab5/zap/report-noauth.html`
  - `labs/lab5/zap/report-auth.html`
  - `labs/lab5/nuclei/nuclei-results.json`
  - `labs/lab5/nikto/nikto-results.txt`
  - `labs/lab5/sqlmap/localhost/log`
  - `labs/lab5/sqlmap/results-03082026_0159pm.csv`
  - `labs/lab5/sqlmap/results-03082026_0200pm.csv`
- Analysis:
  - `labs/lab5/analysis/zap-comparison.txt`
  - `labs/lab5/analysis/dast-summary.txt`
  - `labs/lab5/analysis/correlation.txt`
