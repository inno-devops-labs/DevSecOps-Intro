# Security Analysis: SAST & DAST of OWASP Juice Shop

## Static Application Security Testing with Semgrep

### SAST Tool Effectiveness
Semgrep scanned the OWASP Juice Shop source code (version v19.0.0) using the `security-audit` and `owasp-top-ten` rulesets.  
- **Total files scanned:** over 180 files (full project).  
- **Total findings:** **25** code-level security issues (as reported in `correlation.txt` and `semgrep-report.txt`).  

Semgrep detected various vulnerability types including SQL injection, hardcoded credentials, insecure cryptography, path traversal, cross‑site scripting (XSS), and dangerous code execution patterns.

### Critical Vulnerability Analysis
The five most critical findings (based on severity and potential impact) are listed below:

| Vulnerability Type | File Path | Line | Severity | Description |
|--------------------|-----------|------|----------|-------------|
| SQL Injection | `routes/search.ts` | 23 | **ERROR** | Direct concatenation of user input into an SQL query allows an attacker to extract arbitrary database content. |
| Hardcoded JWT Secret | `lib/insecurity.ts` | 56 | WARNING | A hard‑coded secret key for JWT signing is embedded in the source code, enabling token forgery if discovered. |
| Path Traversal | `routes/fileServer.ts` | 33 | WARNING | The `file` parameter is passed to `res.sendFile` without validation, permitting unauthorized file reads on the server. |
| Eval Injection | `routes/userProfile.ts` | 62 | **ERROR** | User‑supplied data flows into an `eval()` call, which could lead to arbitrary code execution. |
| Cross‑Site Scripting (XSS) | `routes/videoHandler.ts` | 58 | WARNING | The `subs` variable is inserted directly into a `<script>` tag without sanitization, opening the door to script injection. |


## Dynamic Application Security Testing with Multiple Tools

### Authenticated vs Unauthenticated Scanning (ZAP)
The comparison between unauthenticated and authenticated ZAP scans (from `zap-comparison.txt`):

| Metric                     | Unauthenticated | Authenticated |
|----------------------------|-----------------|---------------|
| Total alerts               | 12              | 13            |
| High severity              | 0               | 1             |
| Medium severity            | 2               | 4             |
| Low severity               | 6               | 4             |
| Informational              | 4               | 4             |
| Unique URLs with findings  | 16              | 25            |

**Examples of authenticated/admin endpoints discovered only in the authenticated scan:**
- `/rest/admin/application-configuration` (revealed a private IP address)
- `/rest/user/login` (identified SQL injection in the `email` parameter)
- `/rest/products/search?q=` (also vulnerable to SQL injection)
- Multiple WebSocket endpoints (`/socket.io/`) with session IDs in the URL

**Why authenticated scanning matters:**  
Many critical functions and data are only accessible after login. Without authentication, the scanner cannot reach administrative interfaces, user‑specific resources, or features that require session context. In this case, authenticated scanning found 56% more unique vulnerable URLs and uncovered a high‑risk SQL injection that was completely missed in the unauthenticated scan.

### Tool Comparison Matrix

| Tool     | Findings | Severity Breakdown                  | Best Use Case                               |
|----------|----------|--------------------------------------|---------------------------------------------|
| ZAP (auth) | 13 alert types | High: 1, Medium: 4, Low: 4, Info: 4 | Comprehensive web application scanning with authentication support and active attack simulation. |
| Nuclei   | 1        | Info: 1                              | Fast template‑based detection of known CVEs and misconfigurations. |
| Nikto    | 82       | – (text output only)                 | Quick web server assessment – reveals outdated software, risky files, and configuration flaws. |
| SQLmap   | 0        | –                                   | Specialised deep SQL injection exploitation (did not detect anything in this run, possibly due to Docker limitations or incomplete command). |

### Tool-Specific Strengths

**ZAP (Authenticated)**
- Excels at **comprehensive scanning** – discovered 13 different issue types, including one critical SQL injection.
- Identified **missing security headers** (CSP, X‑Frame‑Options, X‑Content‑Type‑Options) and a **CORS misconfiguration** (`Access-Control-Allow-Origin: *`).
- Example findings: SQL injection in `/rest/products/search` and `/rest/user/login`, private IP disclosure in `/rest/admin/application-configuration`.

**Nuclei**
- **Fast and template‑based** – detected a public Swagger API endpoint that exposes the entire API structure.
- Useful for continuous monitoring and quick regression testing against known vulnerabilities.

**Nikto**
- Specialises in **server misconfiguration and outdated files** – found 82 potential issues, including:
  - `access-control-allow-origin: *` header
  - Missing `X-XSS-Protection` header
  - Existence of backup files and directories like `/ftp/` and `/public/`
  - Potential LFI in outdated plugin paths (though likely false positives for Juice Shop).

**SQLmap**
- Despite not finding any injection in this run, it is the gold standard for deep SQL injection exploitation. When properly configured, it can automatically extract entire database contents from a vulnerable parameter. The lack of results may be due to the JSON payload format or the need for more precise parameters.

---

## SAST/DAST Correlation and Security Assessment

### SAST vs DAST Comparison

| Testing Approach | Total Findings | Vulnerability Types Found |
|------------------|----------------|---------------------------|
| SAST (Semgrep)   | 25             | Hardcoded secrets, insecure crypto, code‑level injection patterns, dangerous functions (`eval`), unquoted template variables. |
| DAST (combined)  | 96 (13+1+82)   | Missing security headers, CORS misconfiguration, information disclosure (private IP, backup files), server version leaks, SQL injection (confirmed). |

**Vulnerability types found ONLY by SAST:**
1. **Hardcoded JWT secret** – stored in source code, never exposed in runtime traffic.
2. **Insecure cryptographic algorithm** (MD5) – used for password hashing, only visible in code.
3. **Eval injection** – `eval()` with user input cannot be detected dynamically unless it actually executes malicious code.
4. **XSS in template expressions** – unquoted Angular variables that are only exploitable in the browser; DAST might not trigger them without a specific payload.

**Vulnerability types found ONLY by DAST:**
1. **Missing security headers** (CSP, X‑Frame‑Options, X‑Content‑Type‑Options) – purely a server configuration issue.
2. **CORS misconfiguration** (`Access-Control-Allow-Origin: *`) – only visible in HTTP responses.
3. **Information disclosure** (private IP, backup file exposure, server version) – depends on the deployment environment.
4. **SQL injection (confirmed exploitable)** – SAST flagged potential SQLi locations, but DAST (ZAP) proved they are reachable and exploitable.

**Why different findings occur:**  
SAST inspects the source code and uncovers issues that exist regardless of the runtime environment (hardcoded secrets, bad coding patterns). DAST tests the live application and reveals configuration mistakes, runtime behaviour, and actual exploitability of code‑level flaws. Neither approach is sufficient alone; together they provide a complete security picture.

### Remediation Recommendations
Based on the correlation analysis:

1. **Fix SQL injections** – replace string concatenation with parameterised queries or an ORM (highlighted by SAST, confirmed by DAST).
2. **Remove hardcoded secrets** – use environment variables or a secrets manager.
3. **Strengthen cryptography** – replace MD5 with bcrypt or Argon2 for password storage.
4. **Configure secure headers** – add `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, and restrict CORS to trusted origins.
5. **Prevent information leakage** – hide server version, remove backup files from public directories, restrict access to `/ftp/` and `/rest/admin/`.