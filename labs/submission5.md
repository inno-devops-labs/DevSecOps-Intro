# Lab 5 -- Security Analysis: SAST & DAST of OWASP Juice Shop

## Task 1 -- Static Application Security Testing with Semgrep

### 1. SAST Tool Effectiveness

Semgrep was configured with `p/security-audit` and `p/owasp-top-ten` rulesets to analyze the OWASP Juice Shop v19.0.0 source code.

- **Total findings:** 25 vulnerabilities detected
- **Severity breakdown:** 7 ERROR (high severity), 18 WARNING (medium severity)
- **Files with findings:** 20 unique source files scanned with results
- **Vulnerability types detected:**
  - SQL Injection (Sequelize injection via user input) -- 6 findings
  - Path Traversal / Insecure File Serving (`res.sendFile` with user input) -- 4 findings
  - Cross-Site Scripting (unquoted template variables, script tag injection) -- 5 findings
  - Hardcoded JWT Secret -- 1 finding
  - Code Injection (`eval` with user-controlled data) -- 1 finding
  - Open Redirect (unvalidated redirect URL) -- 2 findings
  - Directory Listing enabled -- 4 findings
  - Raw HTML format injection -- 1 finding
  - Insecure template attribute -- 1 finding

### 2. Critical Vulnerability Analysis -- Top 5 Findings

| # | Vulnerability Type | File Path | Line | Severity |
|---|---|---|---|---|
| 1 | **SQL Injection** (Sequelize) | `/src/routes/search.ts` | 23 | ERROR |
| 2 | **SQL Injection** (Sequelize) | `/src/routes/login.ts` | 34 | ERROR |
| 3 | **Code Injection** (eval with user data) | `/src/routes/userProfile.ts` | 62 | ERROR |
| 4 | **Hardcoded JWT Secret** | `/src/lib/insecurity.ts` | 56 | WARNING |
| 5 | **Path Traversal** (sendFile with user input) | `/src/routes/fileServer.ts` | 33 | WARNING |

**Details:**
1. **SQL Injection in search route** -- User-controlled query parameter passed directly to Sequelize query, enabling arbitrary SQL execution against the SQLite database.
2. **SQL Injection in login route** -- Email field from login POST request used in raw Sequelize query without parameterization, allowing authentication bypass.
3. **Code Injection in user profile** -- User-controlled data flows into `eval()`, enabling arbitrary JavaScript execution on the server.
4. **Hardcoded JWT Secret** -- The JWT signing secret is hardcoded in source code, allowing anyone with code access to forge authentication tokens.
5. **Path Traversal in file server** -- User input passed to `res.sendFile()` without proper sanitization, potentially allowing access to arbitrary files on the server.

---

## Task 2 -- Dynamic Application Security Testing with Multiple Tools

### 1. Authenticated vs Unauthenticated Scanning

| Metric | Unauthenticated | Authenticated |
|---|---|---|
| **Alert types** | 11 | 13 |
| **Spider URLs found** | ~20 (baseline) | 166 (spider) + 1,108 (AJAX spider) |
| **High severity** | 0 | 1 (SQL Injection) |
| **Medium severity** | 2 | 4 |

**Admin/authenticated endpoints discovered:**
- `/rest/admin/application-configuration` -- admin panel configuration
- `/rest/user/login` -- authentication endpoint (SQL injection found)
- `/api/SecurityAnswers/`, `/api/SecurityQuestions/` -- security question management
- `/rest/basket/`, `/rest/wallet/balance` -- user-specific shopping features
- `/profile`, `/accounting` -- user profile and account management

**Why authenticated scanning matters:**
Authenticated scanning discovered the **SQL Injection** vulnerability (High severity) that was invisible to the unauthenticated scan. The AJAX spider found 1,108 URLs compared to the baseline's limited crawl, revealing the full attack surface including admin panels, user-specific endpoints, and API routes that require session tokens. Without authentication, over 60% of the application's endpoints remain untested.

### 2. Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|---|---|---|---|
| **ZAP (unauth)** | 11 alerts | 0 High, 2 Medium, 6 Low, 3 Info | Quick baseline web app assessment |
| **ZAP (auth)** | 13 alerts | 1 High, 4 Medium, 4 Low, 3 Info (+ 1,274 URLs) | Comprehensive authenticated web app testing |
| **Nuclei** | 1 finding | 1 Info (Swagger API exposure) | Fast known-CVE and exposure detection |
| **Nikto** | 78 findings | Mostly informational (headers, backup files, misconfigs) | Web server misconfiguration assessment |
| **SQLmap** | 1 confirmed SQLi | 1 Critical (Boolean-based blind SQLi on search) | Deep SQL injection exploitation and data extraction |

### 3. Tool-Specific Strengths

**OWASP ZAP:**
- Excels at comprehensive web application scanning with authentication support
- AJAX spider discovers JavaScript-rendered endpoints that traditional crawlers miss
- Active scanner tests for runtime vulnerabilities (XSS, SQLi, CSRF)
- *Example findings:* SQL Injection (High), Missing CSP Header (Medium), Session ID in URL Rewrite (Medium)

**Nuclei:**
- Extremely fast template-based scanning (10K+ templates in ~2 minutes)
- Community-maintained templates for known CVEs and common exposures
- Best for quick checks against known vulnerability patterns
- *Example finding:* Public Swagger API detected at `/api-docs/swagger.json` (info)

**Nikto:**
- Specialized in web server misconfiguration and information disclosure
- Checks for backup files, default files, and server-level issues
- Broad coverage of file/path enumeration
- *Example findings:* Missing X-XSS-Protection header, robots.txt with `/ftp/` entry, 70+ potentially interesting backup/cert files found

**SQLmap:**
- Deep SQL injection detection with automated exploitation
- Confirmed Boolean-based blind SQL injection on `/rest/products/search?q=*`
- Identified SQLite backend and confirmed exploitability
- *Example finding:* `URI parameter '#1*' is vulnerable` with payload `') AND 1016=1016 AND ('wNeJ' LIKE 'wNeJ`

---

## Task 3 -- SAST/DAST Correlation and Security Assessment

### 1. SAST vs DAST Comparison

| Metric | SAST (Semgrep) | DAST (All Tools Combined) |
|---|---|---|
| **Total findings** | 25 | 93 (13 ZAP auth + 1 Nuclei + 78 Nikto + 1 SQLmap) |
| **Approach** | Code-level pattern matching | Runtime behavior analysis |
| **Scan time** | ~3 minutes | ~35 minutes total |

**Vulnerability types found ONLY by SAST:**
1. **Hardcoded JWT Secret** (`insecurity.ts:56`) -- DAST cannot detect secrets embedded in source code; it would need to decompile or access the source
2. **Code Injection via eval()** (`userProfile.ts:62`) -- Semgrep identifies dangerous function calls with tainted input that DAST may not trigger without specific payloads
3. **Open Redirect patterns** (`redirect.ts:19`) -- SAST identifies the code pattern of unvalidated redirects directly, while DAST needs to test redirect parameters

**Vulnerability types found ONLY by DAST:**
1. **Missing Security Headers** (CSP, X-XSS-Protection, X-Content-Type-Options) -- These are deployment/configuration issues not present in source code
2. **Session Management Issues** (Session ID in URL Rewrite) -- Runtime session handling behavior only observable through live traffic
3. **Server Information Disclosure** (backup files, Swagger API exposure, private IP disclosure) -- Server-level misconfigurations invisible to source code analysis

**Why each approach finds different things:**
- **SAST** analyzes code patterns and data flow. It excels at finding implementation bugs (injection sinks, hardcoded secrets, dangerous function calls) but cannot see deployment configuration, network behavior, or runtime state.
- **DAST** tests the running application as a black box. It excels at finding configuration issues (headers, TLS, server misconfigs) and confirming exploitability, but cannot see internal code logic or dead code vulnerabilities.
- **Both** found SQL injection through different lenses: Semgrep identified 6 injection patterns in source code, while SQLmap confirmed 1 exploitable injection at runtime and ZAP's active scan detected it with authentication context.

### Security Recommendations

1. **Immediate (Critical):** Fix SQL injection in `/rest/products/search` and `/rest/user/login` by using parameterized queries
2. **High Priority:** Remove hardcoded JWT secret and use environment variable; eliminate `eval()` usage in user profile
3. **Medium Priority:** Add Content Security Policy, X-Content-Type-Options, and anti-clickjacking headers
4. **DevSecOps Integration:** Run Semgrep in CI/CD pre-commit hooks, ZAP in staging environment, Nuclei for periodic CVE checks, and SQLmap for targeted injection testing when SAST flags database interaction code
