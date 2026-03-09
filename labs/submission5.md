# Lab 5 Submission — SAST & DAST of OWASP Juice Shop


## Task 1 — Static Application Security Testing with Semgrep

Generated artifacts:
- `labs/lab5/semgrep/semgrep-results.json`
- `labs/lab5/semgrep/semgrep-report.txt`
- `labs/lab5/analysis/sast-analysis.txt`

### 1.4 SAST Tool Effectiveness

- **Types of vulnerabilities detected by Semgrep (expected categories, confirm with your output):**
  - Input validation and injection patterns (e.g., unsafe use of query builders, string concatenation in SQL or NoSQL queries)
  - Cross-Site Scripting patterns (e.g., unescaped user input rendered into templates or Angular components)
  - Insecure cryptography usage (weak hash/crypto functions, insecure random)
  - Hardcoded secrets and credentials (tokens, sample passwords, default keys)
  - Insecure configuration patterns (debug flags, overly permissive CORS, missing security headers in code)

- **Coverage:**
  - **Files scanned:** Full Juice Shop v19.0.0 source tree (backend + frontend)
  - **Total findings:** 25
  - **Rule sources:** `p/security-audit`, `p/owasp-top-ten`

Overall, Semgrep gives **good source-level coverage** of Juice Shop’s Node.js/Angular codebase. It is especially useful for catching patterns that may not yet be exploitable in the deployed app but are clearly dangerous from a code perspective (e.g., potential injection sinks, dangerous APIs, missing validation).

### 1.5 Top 5 Critical Semgrep Findings

| Rank | Vulnerability Type | File (path) | Line(s) | Severity | Notes / Risk |
|---:|---|---|---|---|---|
| 1 | Hardcoded JWT secret | `/src/lib/insecurity.ts` | 56 | Blocking | JWT signing key is hardcoded; if the code leaks, attackers can forge tokens for any user (full auth bypass). |
| 2 | SQL injection via Sequelize query (string concatenation) | `/src/data/static/codefixes/dbSchemaChallenge_1.ts` | 5 | Blocking | Raw SQL concatenates `criteria` into the WHERE clause, allowing arbitrary SQL injection. |
| 3 | SQL injection via Sequelize query (template literal) | `/src/data/static/codefixes/dbSchemaChallenge_3.ts` | 11 | Blocking | Template literal with `${criteria}` in the query enables SQL injection when user input is not sanitized. |
| 4 | SQL injection in UNION challenge | `/src/data/static/codefixes/unionSqlInjectionChallenge_1.ts` | 6 | Blocking | UNION-based query built from `${criteria}` can be abused to exfiltrate data via injected `UNION SELECT` statements. |
| 5 | Path traversal via `res.sendFile` | `/src/routes/fileServer.ts` | 33 | Blocking | User-controlled filename flows into `res.sendFile('ftp/' + file)`, enabling directory traversal within the FTP directory. |

**Commentary:**

- These findings represent the **most impactful code-level issues**, either because they expose sensitive data (e.g., secrets), enable injection, or weaken authentication.
- Semgrep’s ability to **pinpoint file + line** makes it straightforward to send precise remediation tickets to developers and to add unit tests to prevent regressions.

---

## Task 2 — Dynamic Application Security Testing with Multiple Tools 


## Analysis Sections

### 2.6 Authenticated vs Unauthenticated Scanning (ZAP)

- **URL discovery (from `labs/lab5/analysis/zap-comparison.txt`):**
  - Unauthenticated baseline: 95 URLs discovered.
  - Authenticated spider: 145 URLs; AJAX spider: 352 URLs; combined authenticated discovery: 497 URLs.
  - This is roughly a 4.2× increase in discovered URLs compared to the unauthenticated baseline, showing how much more attack surface is revealed after login.
- **Examples of authenticated/admin endpoints:**
  - `/rest/admin/application-configuration`
  - `/rest/admin/users`
  - `/rest/basket/` and `/rest/orders/`

**Why authenticated scanning matters:**

- Many critical vulnerabilities (privilege escalation, weak access controls, IDORs) are only reachable **after login**.
- Authenticated ZAP runs uncovered significantly more URLs and attack surface compared to the baseline scan.
- This demonstrates that **DevSecOps pipelines must include authenticated scans** for realistic coverage of business logic and admin flows.

### 2.7 Tool Comparison Matrix

| Tool | Total Findings | Severity Breakdown | Best Use Case |
|---|---:|---|---|
| ZAP (no auth) | ≈3 | high=0, medium=3 | Quick baseline of public endpoints; basic header and content checks. |
| ZAP (auth) | 14 | high=1, medium=5, low=4, info=4 | Deep scan including authenticated/admin areas; finds modern web and session issues. |
| Nuclei | 2 | both info-level template matches | Fast checks for known exposures (Swagger UI, recruiting header). |
| Nikto | 84 | mostly informational/low | Web server and file-exposure misconfigurations. |
| SQLmap | 1 | confirmed SQL injection (critical) | Deep SQL injection detection and exploitation on the search endpoint. |

### 2.8 Tool-Specific Strengths (with Examples)

- **ZAP:**
  - Strengths: Integrated spider + active scanner; rich HTML reports; supports authentication and automation.
  - Example findings: Dangerous JS functions in `main.js`/`vendor.js`, missing CSP header on `/`, cross-domain misconfiguration on `/sitemap.xml`.

- **Nuclei:**
  - Strengths: Very fast; leverages community templates to catch known CVEs and misconfigurations.
  - Example findings: Public Swagger UI at `/api-docs/swagger.json` and `X-Recruiting: /#/jobs` header.

- **Nikto:**
  - Strengths: Focused on HTTP server and configuration weaknesses.
  - Example findings: Numerous potential backup/cert/archive files (e.g. `.jks`, `.pem`, `.tar`, `.tgz`) and missing CSP/HSTS/Permissions-Policy/Referrer-Policy headers.

- **SQLmap:**
  - Strengths: Specialized SQL injection detection and exploitation, including DB schema extraction.
  - Example findings: Confirmed boolean-based SQL injection on `/rest/products/search?q=*`, recorded in `results-03092026_0717pm.csv`.

---

## Task 3 — SAST/DAST Correlation and Security Assessment


### 3.2 SAST vs DAST Comparison

- **Total findings:**
  - SAST (Semgrep): 25 findings
  - Combined DAST (ZAP + Nuclei + Nikto + SQLmap): 100 findings 

- **Examples of vulnerabilities found only by SAST:**
  - Hardcoded secrets in configuration or source files.
  - Insecure cryptographic usage (e.g., weak hashes or deprecated algorithms).
  - Dangerous internal helper functions not directly reachable over HTTP but still risky.

- **Examples of vulnerabilities found only by DAST:**
  - Missing or weak security headers (CSP, HSTS, X-Frame-Options).
  - Authentication/session management issues visible at runtime.
  - SQL injection confirmed by SQLmap on production-like endpoints.

**Why each approach finds different things:**

- SAST has **full code visibility**, including dead code and internal helpers, and can reason about patterns that may become exploitable in future features.
- DAST sees only the **deployed, reachable attack surface** and focuses on actual HTTP interactions, runtime configurations, and environment-specific issues.
- Together, they provide **defense in depth**: SAST for early, developer-friendly feedback; DAST for realistic exploitation and misconfiguration detection.

