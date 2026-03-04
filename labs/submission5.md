# Lab 5 Submission - SAST and DAST Security Analysis

## Scope and Setup

- Target application: `bkimminich/juice-shop:v19.0.0`
- SAST source analyzed in: `labs/lab5/semgrep/juice-shop`
- DAST target URL: `http://localhost:3000`
- DAST artifacts:
  - `labs/lab5/zap/*`
  - `labs/lab5/nuclei/nuclei-results.json`
  - `labs/lab5/nikto/nikto-results.txt`
  - `labs/lab5/sqlmap/localhost/*`

---

## Task 1 - SAST Analysis with Semgrep

### 1) SAST Tool Effectiveness

Semgrep was run with `p/security-audit` and `p/owasp-top-ten` rulesets.

- Files scanned: **476**
- Total findings: **21**
- Severity distribution: **7 ERROR**, **14 WARNING**
- Main vulnerability categories detected:
  - SQL Injection patterns (CWE-89) - 6
  - Path Traversal / unsafe file serving (CWE-73) - 4
  - Directory Listing exposure (CWE-548) - 4
  - XSS-related patterns (CWE-79) - 3
  - Open Redirect (CWE-601) - 2
  - Hardcoded Credential (CWE-798) - 1
  - Eval Injection (CWE-95) - 1

Semgrep gave strong coverage for code-level vulnerabilities and insecure coding patterns that are difficult to prove from runtime-only scanning.

### 2) Critical Vulnerability Analysis (Top 5)

| # | Vulnerability Type | File and Line | Severity | Why Critical |
|---|---|---|---|---|
| 1 | SQL Injection (tainted Sequelize query) | `routes/login.ts:34` | ERROR | Authentication endpoint logic is SQLi-prone and can allow auth bypass or data disclosure. |
| 2 | SQL Injection (tainted Sequelize query) | `routes/search.ts:23` | ERROR | Search endpoint is directly exposed and can be exploited remotely. |
| 3 | Eval Injection / Code Execution Risk | `routes/userProfile.ts:62` | ERROR | Request-controlled data reaches `eval`, risking arbitrary code execution. |
| 4 | Hardcoded JWT Secret / Credential | `lib/insecurity.ts:56` | WARNING | Embedded secret material can be leaked and reused for token forgery. |
| 5 | Path Traversal via `res.sendFile` | `routes/fileServer.ts:33` | WARNING | User-controlled path usage can expose arbitrary files from server filesystem. |

---

## Task 2 - DAST Analysis with Multiple Tools

### 1) Authenticated vs Unauthenticated Scanning

From `labs/lab5/analysis/zap-comparison.txt`:

- Unauthenticated URL discovery: **95 URLs**
- Authenticated URL discovery: **1143 URLs** (`spider=112`, `ajax=1031`)
- Coverage growth: **+1103%**

Examples of authenticated/admin endpoints discovered:

- `http://localhost:3000/rest/admin/application-configuration`
- `http://localhost:3000/rest/user/login`

Why authenticated scanning matters:

- It reaches role-protected and session-bound paths invisible to anonymous scans.
- It significantly increases attack surface visibility (especially with AJAX spider).
- It reveals business-logic and privileged configuration risks that baseline scans miss.

### 2) Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|---|---:|---|---|
| ZAP (authenticated report) | 11 | High=0, Medium=4, Low=4, Info=3 | Full web app assessment with login/session context |
| Nuclei | 3 | Critical=0, High=0, Medium=0, Low=0, Info=2, Unknown=1 | Fast template-based detection of known exposures/CVEs |
| Nikto | 14 | Server/header/content checks (text output) | Web server and deployment misconfiguration checks |
| SQLmap | 1 confirmed SQLi endpoint | SQLi endpoint=1, dumped tables=16 | Deep SQL injection validation and data extraction |

### 3) Tool-Specific Strengths and Examples

**ZAP**

- Strength: broad web coverage, authenticated crawling, rich passive alerting.
- Examples:
  - `Content Security Policy (CSP) Header Not Set` (Medium)
  - `Session ID in URL Rewrite` (Medium)

**Nuclei**

- Strength: very fast checks with community templates.
- Examples:
  - `swagger-api` exposure at `http://localhost:3000/api-docs/swagger.yaml`
  - `wildcard-dns-detect` (`info`)

**Nikto**

- Strength: practical server hardening and header/config checks.
- Examples:
  - ETag inode leakage on `/`
  - Robots-related exposure for `/ftp/` and interesting directory/content findings

**SQLmap**

- Strength: reliable SQLi confirmation and exploitation workflow.
- Examples:
  - Confirmed boolean-based blind SQLi on `GET /rest/products/search?q=*`
  - Enumerated SQLite schema and dumped data into `labs/lab5/sqlmap/localhost/dump/SQLite_masterdb/`

---

## Task 3 - SAST/DAST Correlation and Security Assessment

### 1) SAST vs DAST Comparison

- SAST findings: **21**
- Combined DAST findings (ZAP auth + Nuclei + Nikto + SQLmap): **29**

Vulnerability types found **only by SAST** in this lab:

- Hardcoded credential/secret patterns in source code
- Dangerous `eval` usage and code execution patterns
- Unsafe file path handling (`sendFile`) before active exploitation

Vulnerability types found **only by DAST** in this lab:

- Runtime header/configuration weaknesses (CSP, clickjacking/session handling issues)
- Public API/documentation exposure (Swagger endpoint)
- Confirmed SQLi exploitability with live DB interaction and data dump

Why results differ:

- SAST analyzes source semantics and catches risky code paths pre-runtime.
- DAST observes real behavior, deployment config, and runtime response handling.
- Together they provide stronger coverage than either approach alone.

### 2) Security Recommendations

1. Parameterize SQL queries everywhere (`login`, `search`, and challenge code paths).
2. Remove hardcoded secrets and load sensitive values from environment or secret manager.
3. Eliminate `eval` usage and replace with strict safe parsing/dispatch logic.
4. Validate and canonicalize file paths before any file-serving operation.
5. Enforce security headers (CSP, COEP, clickjacking protections) at reverse proxy/app layer.
6. Keep authenticated DAST in CI/CD for staging, and run targeted SQLmap tests on risky endpoints.

