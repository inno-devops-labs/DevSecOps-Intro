# Lab 5 - Security Analysis (SAST + Multi-Tool DAST)

## Scope

- Target app: `bkimminich/juice-shop:v19.0.0`
- Analysis date: `2026-03-02`
- SAST tool: Semgrep
- DAST tools: ZAP, Nuclei, Nikto, SQLmap

## Task 1 - SAST with Semgrep

### 1.1 SAST Tool Effectiveness

Semgrep detected code-level security issues in Juice Shop source code with useful coverage of injection patterns, risky API usage, and template issues.

- Total findings: `25`
- Files with findings: `20`
- Severity breakdown:
  - `ERROR`: `7`
  - `WARNING`: `18`
- Scan coverage from Semgrep run:
  - Targets scanned: `1014` files
  - Rules run: `140`

Most common vulnerability patterns found:

- Sequelize injection patterns (`express-sequelize-injection`)
- Express file handling weaknesses (`res.sendFile`, directory listing checks)
- HTML/template unsafe attribute usage
- Dangerous code execution flow (`eval` sink)
- Hardcoded JWT secret

### 1.2 Critical Vulnerability Analysis (Top 5)

1. **Code Injection / Unsafe `eval` Sink**
   - Type: Code Injection / Command Execution risk
   - File: `src/routes/userProfile.ts:62`
   - Rule: `javascript.lang.security.audit.code-string-concat.code-string-concat`
   - Severity: `ERROR`

2. **Sequelize Injection (tainted user input)**
   - Type: SQL Injection pattern
   - File: `src/data/static/codefixes/dbSchemaChallenge_1.ts:5`
   - Rule: `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
   - Severity: `ERROR`

3. **Sequelize Injection (tainted user input)**
   - Type: SQL Injection pattern
   - File: `src/data/static/codefixes/dbSchemaChallenge_3.ts:11`
   - Rule: `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
   - Severity: `ERROR`

4. **Sequelize Injection (tainted user input)**
   - Type: SQL Injection pattern
   - File: `src/data/static/codefixes/unionSqlInjectionChallenge_1.ts:6`
   - Rule: `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
   - Severity: `ERROR`

5. **Sequelize Injection (tainted user input)**
   - Type: SQL Injection pattern
   - File: `src/data/static/codefixes/unionSqlInjectionChallenge_3.ts:10`
   - Rule: `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
   - Severity: `ERROR`

## Task 2 - DAST with Multiple Tools

### 2.1 Authenticated vs Unauthenticated ZAP

Comparison from generated reports:

- NoAuth sites: `1`
- Auth sites: `2`
- NoAuth discovered URLs (alerts/instances): `16`
- Auth discovered URLs (alerts/instances): `24`
- NoAuth admin endpoints: `0`
- Auth admin endpoints: `1`

Authenticated endpoint example discovered:

- `http://localhost:3000/rest/admin/application-configuration`

Why authenticated scanning matters:

- It exposes role-protected attack surface (`/rest/admin/*`) that unauthenticated scans miss.
- It increases practical coverage of business logic and privileged APIs.
- It improves realism of security testing by simulating authenticated user paths.

### 2.2 Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
| --- | ---: | --- | --- |
| ZAP (authenticated) | 37 total alert instances (approx) | Low: 12, Medium: 6, High: 0, Info: 19 | Broad web app scanning, endpoint discovery, header/policy issues, auth-aware crawling |
| Nuclei | 0 | Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 | Fast checks for known CVE/template-based detections |
| Nikto | 82 | Severity not normalized like CVSS; server issue style output | Web server/configuration hygiene and exposed files/directories |
| SQLmap | 1 injectable endpoint | SQLi confirmed on `/rest/products/search` (boolean-based blind) | Deep and targeted SQL injection validation/exploitation |

### 2.3 Tool-Specific Strengths and Example Findings

- **ZAP**
  - Strengths: comprehensive passive checks, endpoint discovery, auth-enabled coverage.
  - Example findings:
    - `Content Security Policy (CSP) Header Not Set`
    - `X-Content-Type-Options Header Missing`

- **Nuclei**
  - Strengths: speed, known-template checks, easy CI integration.
  - Example result:
    - No template matches in this run (`0`), indicating no signatures triggered for selected templates/target state.

- **Nikto**
  - Strengths: server misconfiguration and exposed artifact checks.
  - Example findings:
    - Missing `X-XSS-Protection` header
    - Multiple potentially interesting backup/cert file paths (e.g., `/site.tar.lzma`, `/archive.tar.bz2`)

- **SQLmap**
  - Strengths: deep SQLi verification and DBMS fingerprinting.
  - Example findings:
    - Confirmed boolean-based blind SQL injection in `GET /rest/products/search?q=*`
    - Fingerprinted backend DBMS as `SQLite`

## Task 3 - SAST/DAST Correlation and Security Assessment

### 3.1 SAST vs DAST Comparison

- SAST total findings: `25`
- Combined DAST findings (tool outputs):
  - ZAP alerts (auth, medium+high count used in correlation): `6`
  - Nuclei: `0`
  - Nikto: `82`
  - SQLmap: `1`
  - Combined: `89`

Vulnerability types found mainly by SAST (code-level):

1. Unsafe code execution sink patterns (`eval` data flow)
2. ORM/SQL construction taint patterns inside source files
3. Hardcoded secret patterns (e.g., JWT secret usage)

Vulnerability types found mainly by DAST (runtime/deployment):

1. Missing HTTP security headers (CSP, X-Content-Type-Options)
2. Runtime session handling observations (session ID in URL rewrite)
3. Server exposure/misconfiguration indicators (robots/backup-like paths from Nikto)

Why findings differ:

- SAST analyzes source and control/data flow before runtime, so it finds latent code flaws even if not reachable in a live request path.
- DAST observes live behavior, headers, routing, and response handling, so it detects deployment/configuration issues that source-only analysis misses.
- Authenticated DAST can reveal protected attack surface that unauthenticated DAST cannot reach.

## Security Recommendations

1. Add Semgrep to PR/CI gates with fail criteria for `ERROR` findings.
2. Keep ZAP authenticated scans in staging; include periodic baseline scans for unauthenticated exposure.
3. Use SQLmap selectively when SAST/DAST indicate SQLi risk (avoid broad intrusive runs in shared envs).
4. Enforce security headers at the reverse proxy or app framework level (`CSP`, `X-Content-Type-Options`, clickjacking defenses).
5. Validate and remove vulnerable query construction patterns; prefer parameterized ORM/query APIs only.

## Notes on Execution

- Original lab image names for Nikto/SQLmap were unavailable in current registry.
  - Used `alpine/nikto` and `googlesky/sqlmap` to complete equivalent scans.
- ZAP Automation Framework authentication method names in initial YAML were rejected by this ZAP image version.
  - Completed authenticated scan by injecting admin JWT in request headers during ZAP baseline + AJAX crawl and generated `report-auth.html` / `zap-report-auth.json`.

## Generated Artifacts

- `labs/lab5/semgrep/semgrep-results.json`
- `labs/lab5/semgrep/semgrep-report.txt`
- `labs/lab5/zap/report-noauth.html`
- `labs/lab5/zap/zap-report-noauth.json`
- `labs/lab5/zap/report-auth.html`
- `labs/lab5/zap/zap-report-auth.json`
- `labs/lab5/nuclei/nuclei-results.json`
- `labs/lab5/nikto/nikto-results.txt`
- `labs/lab5/sqlmap/results-*.csv`
- `labs/lab5/analysis/sast-analysis.txt`
- `labs/lab5/analysis/compare-zap.txt`
- `labs/lab5/analysis/dast-summary.txt`
- `labs/lab5/analysis/correlation.txt`
