# Lab 5 Submission — SAST & DAST Security Analysis of OWASP Juice Shop

**Target Application:** OWASP Juice Shop v19.0.0 (`bkimminich/juice-shop:v19.0.0`)

---

## Task 1 — Static Application Security Testing with Semgrep

### 1.1 SAST Tool Effectiveness

**Tool:** Semgrep with rulesets `p/security-audit` and `p/owasp-top-ten`

**Coverage:**
- **Total findings:** 25
- **ERROR severity:** 7
- **WARNING severity:** 18

**Vulnerability types detected by Semgrep:**

| Type | Count | Severity |
|------|-------|----------|
| SQL Injection (Sequelize user-input taint) | 6 | ERROR |
| Eval Injection (user input → `eval()`) | 1 | ERROR |
| Hardcoded JWT Secret | 1 | WARNING |
| Path Traversal via `res.sendFile` | 4 | WARNING |
| Cross-Site Scripting (raw HTML format) | 1 | WARNING |
| Open Redirect | 2 | WARNING |
| Unquoted template variable (XSS vector) | 3 | WARNING |
| Other | 7 | WARNING |

**Analysis:** Semgrep scans source code statically, identifying dangerous patterns before deployment. It is particularly strong at finding injection vulnerabilities, hardcoded secrets, and insecure API usage patterns across the entire codebase — including files that may never be directly hit by a running scanner.

---

### 1.2 Critical Vulnerability Analysis — Top 5 Findings

**Finding 1: SQL Injection — Login endpoint**
- **Vulnerability Type:** SQL Injection (Sequelize unsanitized user input)
- **File Path:** `src/routes/login.ts`
- **Line Number:** 34
- **Severity:** ERROR
- **Description:** A Sequelize query is constructed with user-supplied input without parameterization. An attacker can manipulate the `email` field to bypass authentication or dump the database.
- **Rule ID:** `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`

**Finding 2: SQL Injection — Search endpoint**
- **Vulnerability Type:** SQL Injection (Sequelize unsanitized user input)
- **File Path:** `src/routes/search.ts`
- **Line Number:** 23
- **Severity:** ERROR
- **Description:** The product search query passes raw user input directly into a Sequelize query, enabling Boolean-based and Union-based SQL injection.
- **Rule ID:** `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`

**Finding 3: Eval Injection (Remote Code Execution)**
- **Vulnerability Type:** Code Injection via `eval()`
- **File Path:** `src/routes/userProfile.ts`
- **Line Number:** 62
- **Severity:** ERROR
- **Description:** Data from an Express web request flows into `eval()`. A user-controlled value here leads to arbitrary code execution in the server process context.
- **Rule ID:** `javascript.lang.security.audit.code-string-concat.code-string-concat`

**Finding 4: Hardcoded JWT Secret**
- **Vulnerability Type:** Hardcoded Credential / Secret
- **File Path:** `src/lib/insecurity.ts`
- **Line Number:** 56
- **Severity:** WARNING
- **Description:** A JWT signing secret is hardcoded in source code. Anyone with access to the repository can forge valid JWT tokens for any user, including admin accounts.
- **Rule ID:** `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret`

**Finding 5: Path Traversal via `res.sendFile`**
- **Vulnerability Type:** Path Traversal
- **File Path:** `src/routes/fileServer.ts`
- **Line Number:** 33
- **Severity:** WARNING
- **Description:** User-controlled input is passed to `res.sendFile` without validation. An attacker can traverse the server's file system and read arbitrary files (e.g., `/etc/passwd`).
- **Rule ID:** `javascript.express.security.audit.express-res-sendfile.express-res-sendfile`

---

## Task 2 — Dynamic Application Security Testing with Multiple Tools

### 2.1 Authenticated vs Unauthenticated Scanning

The unauthenticated ZAP baseline scan was run against `http://localhost:3000`. Because Juice Shop stores JWT tokens in `localStorage` rather than cookies, full authenticated scanning via ZAP's automation framework requires a script-based auth approach. The baseline scan with AJAX spider still provides substantial coverage.

**Comparison:**

| Metric | Unauthenticated Scan |
|--------|---------------------|
| Total alerts | 17 |
| High | 0 |
| Medium | 6 |
| Low | 5 |
| Informational | 6 |

**Admin/protected endpoints — why authenticated scanning matters:**

Even without authenticated ZAP scanning, ZAP discovered `/ftp/` (backup files accessible without auth) and the API endpoints exposed via the AJAX spider. With authentication, a scanner would additionally reach:
- `http://localhost:3000/rest/admin/application-configuration`
- `http://localhost:3000/rest/admin/users`
- `http://localhost:3000/api/Users` (all user data)
- Order history, payment, wallet endpoints

Authenticated scanning is critical because:
1. **Wider attack surface** — ~60% of application functionality is behind a login.
2. **Privilege escalation** — only authenticated scans reveal whether normal users can reach admin endpoints.
3. **Business logic flaws** — many vulnerabilities (e.g., accessing another user's basket) require a valid session.
4. **Compliance** — OWASP ASVS Level 2+ and PCI DSS require authenticated testing.

---

### 2.2 Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|------|----------|--------------------|--------------|
| **ZAP** | 17 | High: 0, Medium: 6, Low: 5, Info: 6 | Comprehensive web app scanning with passive+active analysis, excellent for CI/CD pipelines |
| **Nuclei** | 3 | Info: 3 | Fast CVE/template-based scanning; best for known-vulnerability detection at scale |
| **Nikto** | 11 | Server issues: 11 | Web server misconfiguration, header leakage, exposed directories |
| **SQLmap** | 1 | Critical SQL injection: 1 | Deep SQL injection analysis, database fingerprinting, data extraction |

---

### 2.3 Tool-Specific Strengths

#### ZAP (OWASP ZAP) — 17 findings

ZAP excels at automated web application testing combining passive scanning (observing traffic) with active scanning (sending attack payloads). Its AJAX spider executes JavaScript and finds endpoints that traditional crawlers miss.

**Example findings:**
1. **CORS Misconfiguration** *(Medium/High)* — The `Access-Control-Allow-Origin: *` header allows any origin to make cross-site requests to the API, enabling potential data theft from authenticated users.
2. **Content Security Policy (CSP) Header Not Set** *(Medium/High)* — No CSP header is set, meaning the browser places no restrictions on which scripts can execute. This dramatically worsens the impact of any XSS vulnerability found elsewhere.
3. **Backup File Disclosure** *(Medium)* — ZAP discovered `/ftp/` directory accessible without authentication, containing potentially sensitive backup files.

#### Nuclei — 3 findings

Nuclei uses a community-maintained template library (10,000+ templates) to detect known vulnerabilities, misconfigurations, and exposed technologies at high speed.

**Example findings:**
1. **Public Swagger API detected** *(Info)* — The Juice Shop exposes its full REST API documentation at `/api-docs`, which an attacker can use to enumerate all endpoints and their parameters.
2. **Missing Subresource Integrity** *(Info)* — External scripts are loaded without SRI hashes, allowing a CDN compromise to inject malicious code into every visitor's browser.
3. **External Service Interaction** *(Info)* — The application makes outbound calls that could be leveraged for SSRF (Server-Side Request Forgery) attacks.

#### Nikto — 11 findings

Nikto specialises in server-level misconfigurations, outdated software headers, and exposed infrastructure files. It runs 6700+ checks quickly and without needing credentials.

**Example findings:**
1. **Server leaks inodes via ETags** — The `ETag` header reveals file system inode numbers, giving attackers internal filesystem information useful for further attacks.
2. **`/ftp/` returns HTTP 200 (not 403)** — The FTP directory is publicly accessible. Nikto confirms this by checking the HTTP status — a file/directory that should be forbidden is open.
3. **Uncommon headers (`x-recruiting`, broad `Access-Control-Allow-Methods`)** — The server exposes `GET,HEAD,PUT,PATCH,POST,DELETE` via OPTIONS, unnecessarily expanding the attack surface.

#### SQLmap — 1 confirmed SQL injection

SQLmap automates SQL injection detection and exploitation. It uses multiple techniques (Boolean-based, Time-based, Error-based, Union-based) and can extract the entire database once a vulnerability is confirmed.

**Example finding:**
1. **SQL Injection in `/rest/products/search?q=*`** — SQLmap confirmed a Boolean+Time-based blind SQL injection in the `q` GET parameter. Using `--technique=BT` and `--dbms=sqlite`, it identified the underlying SQLite database and can dump all tables including the `Users` table with bcrypt-hashed passwords.

---

## Task 3 — SAST/DAST Correlation and Security Assessment

### 3.1 Total Findings Summary

| Approach | Tool | Findings |
|----------|------|----------|
| SAST | Semgrep | **25** code-level findings |
| DAST | ZAP | **17** runtime alerts |
| DAST | Nuclei | **3** template matches |
| DAST | Nikto | **11** server issues |
| DAST | SQLmap | **1** confirmed SQL injection |
| **DAST Total** | Combined | **32** |

SAST found **25** code-level vulnerabilities; combined DAST tools found **32** runtime issues — demonstrating that the two approaches have low overlap and are genuinely complementary.

---

### 3.2 Vulnerability Types Found ONLY by SAST

**1. Eval Injection (RCE) — `src/routes/userProfile.ts:62`**
SAST found data flowing from an HTTP request into `eval()`. At runtime, DAST tools see only HTTP responses — they cannot trace data flow through the server-side code to detect this dangerous pattern. Unless DAST sends a payload that happens to trigger the `eval` path and returns a detectable side-effect, it will miss it.

**2. Hardcoded JWT Secret — `src/lib/insecurity.ts:56`**
A hardcoded secret is invisible at runtime — the application signs tokens and they appear valid. DAST tools have no way to extract a value embedded in source code. SAST reads every line and flags it immediately, regardless of whether the endpoint is ever called.

**3. SQL Injection code patterns in challenge fix files — `src/data/static/codefixes/`**
Semgrep flagged SQL injection patterns in code paths that are not exposed as live HTTP endpoints (challenge code-fix variants). DAST cannot scan dead code or unused routes; SAST covers 100% of the file tree.

---

### 3.3 Vulnerability Types Found ONLY by DAST

**1. CORS Misconfiguration (runtime header)**
The `Access-Control-Allow-Origin: *` header is set at the framework/middleware level, not in application source code. Semgrep does not scan `package.json` dependency config or Express middleware options that produce this header. ZAP sees the actual HTTP response and flags it immediately.

**2. Missing Content-Security-Policy header**
CSP is a server-response header configured outside the application logic — typically in a reverse proxy, web framework config, or middleware. SAST has no visibility into what headers are actually emitted at runtime; ZAP observes the live response and flags its absence.

**3. Exposed `/ftp/` directory (server misconfiguration)**
Both Nikto and ZAP found the `/ftp/` directory accessible over HTTP returning `200 OK`. This is a deployment/configuration issue — the static file server is serving a directory it shouldn't. The source code shows the route exists, but only a live scanner can confirm it is reachable and unprotected in the deployed instance.

---

### 3.4 Why Each Approach Finds Different Things

| | SAST | DAST |
|-|------|------|
| **When** | Before deployment (dev/CI stage) | After deployment (staging/prod) |
| **What it sees** | Full source code, all branches | Only reachable HTTP endpoints |
| **Finds** | Logic bugs, secrets, injection patterns in code | Headers, config, auth flaws, runtime behavior |
| **Misses** | Deployment config, server headers | Dead code, secrets in source, unused routes |
| **Speed** | Fast (~minutes for a repo) | Slow for active scans (hours) |
| **False positives** | Higher (not all flagged code is reachable) | Lower (confirms exploitability) |

**Recommendation:** Use SAST in the CI pipeline on every PR/commit for immediate developer feedback. Run DAST (ZAP baseline at minimum) on every deployment to staging. Run full authenticated DAST + Nuclei + SQLmap before major releases. The two approaches together provide defense-in-depth across the entire SDLC.

---

## Security Recommendations

Based on the combined SAST + DAST findings, the following fixes are prioritised by severity:

| Priority | Issue | Fix |
|----------|-------|-----|
| 🔴 Critical | SQL Injection in `login.ts` and `search.ts` | Use Sequelize parameterized queries everywhere |
| 🔴 Critical | Eval injection in `userProfile.ts:62` | Remove `eval()`; use safe alternatives |
| 🔴 Critical | Hardcoded JWT secret in `insecurity.ts:56` | Move to environment variable / secret vault |
| 🟠 High | No Content-Security-Policy header | Add strict CSP via helmet.js |
| 🟠 High | CORS `Allow-Origin: *` | Restrict to known origins only |
| 🟡 Medium | Path traversal via `res.sendFile` | Validate and canonicalize paths; use `express.static` safely |
| 🟡 Medium | Exposed `/ftp/` directory | Block directory listing; require auth or remove route |
| 🟢 Low | Missing SRI hashes on external scripts | Add `integrity` attributes or self-host all assets |