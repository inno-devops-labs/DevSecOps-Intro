# Lab 5 Submission — SAST & DAST Security Analysis of OWASP Juice Shop

---

## Task 1: SAST with Semgrep

### 1.1 Tool Effectiveness

Semgrep was run against the OWASP Juice Shop v19.0.0 source code using two rule sets:
- `p/security-audit` — general security audit patterns
- `p/owasp-top-ten` — OWASP Top 10 vulnerability patterns

**Results summary:**

| Metric | Value |
|--------|-------|
| Total findings | 25 |
| ERROR severity | 7 |
| WARNING severity | 18 |
| Rule sets applied | 2 (security-audit, owasp-top-ten) |

Semgrep scanned TypeScript, JavaScript, and Handlebars template files across the entire source tree. It detected code-level vulnerabilities including XSS patterns, open redirects, path traversal, and directory listing misconfigurations — all before the application is deployed.

### 1.2 Top 5 Critical Findings

| # | Vulnerability Type | File | Line | Severity |
|---|-------------------|------|------|----------|
| 1 | Unquoted Template Variable (XSS) | `views/dataErasureForm.hbs` | 21 | WARNING |
| 2 | Directory Listing Enabled | `server.ts` | 269, 273, 277, 281 | WARNING |
| 3 | XSS via Unsanitized `<script>` Tag | `routes/videoHandler.ts` | 58, 71 | WARNING |
| 4 | Open Redirect via User-Controlled Input | `routes/redirect.ts` | 19 | WARNING |
| 5 | Path Traversal via `res.sendFile` | `routes/quarantineServer.ts` | 14 | WARNING |

**Details:**

1. **Unquoted Template Variable (XSS)** — `views/dataErasureForm.hbs:21`  
   A Handlebars template variable is used as an HTML attribute without quotes. An attacker can inject custom JavaScript event handlers (e.g., `onmouseover=alert(1)`).

2. **Directory Listing Enabled** — `server.ts:269-281`  
   Multiple `serveIndex()` calls expose directory listings for `/ftp`, `/encryptionkeys`, and other paths. This leaks sensitive file names and backup files to unauthenticated users.

3. **XSS via Script Tag** — `routes/videoHandler.ts:58,71`  
   The variable `subs` (subtitle content) is injected directly into a `<script>` tag without sanitization, making it susceptible to stored XSS.

4. **Open Redirect** — `routes/redirect.ts:19`  
   User-supplied `query` parameter is passed directly to `res.redirect()` without allowlist validation. An attacker can craft phishing URLs that appear to originate from the trusted domain.

5. **Path Traversal** — `routes/quarantineServer.ts:14`  
   User input is passed to `res.sendFile()` without path canonicalization or directory restriction. An attacker can read arbitrary files from the server filesystem using `../` sequences.

---

## Task 2: DAST with Multiple Tools

### 2.1 Authenticated vs Unauthenticated Scanning (ZAP)

The unauthenticated ZAP baseline scan was run against `http://localhost:3000`.

| Metric | Unauthenticated Scan |
|--------|---------------------|
| Total alerts | 11 |
| Medium severity | 2 |
| Low severity | 6 |
| Informational | 3 |
| Endpoints scanned | 72 |

**Key findings from unauthenticated scan:**
- `Content Security Policy (CSP) Header Not Set` — Medium — affects all pages
- `Cross-Domain Misconfiguration (CORS *)` — Medium — `Access-Control-Allow-Origin: *` allows any origin to read API responses
- `Cross-Domain JavaScript Source File Inclusion` — Low — external CDN scripts loaded from `cdnjs.cloudflare.com`
- `Cross-Origin-Embedder-Policy Header Missing` — Low

**Why authenticated scanning matters:**  
Without authentication, a scanner only sees public endpoints. With authentication, it can discover admin panels (`/rest/admin/application-configuration`), user-specific API routes (basket, orders, payment, profile), and privilege escalation vectors that are invisible to unauthenticated tools. Authenticated scanning typically reveals 60%+ more attack surface in applications like Juice Shop that have role-based access control.

### 2.2 Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|------|----------|--------------------|---------------|
| ZAP (unauthenticated) | 11 alerts | 2 Medium, 6 Low, 3 Info | Comprehensive HTTP-level scanning, header analysis, CORS detection |
| Nuclei | 0 | — | Fast CVE template matching; Juice Shop v19 has no known unpatched CVEs in the template database |
| Nikto | ~150 entries (10 real) | Mix of real issues + FP | Web server misconfiguration, exposed directories, missing headers |
| SQLmap | 2 injection points confirmed | Critical | Deep SQL injection analysis with database extraction |

> **Nuclei note:** Nuclei returned 0 findings because its templates target known CVEs and specific version fingerprints. Juice Shop's vulnerabilities are intentional design flaws, not unpatched known CVEs — so Nuclei, which excels at CVE matching, finds nothing here. This is an important tool-selection lesson.

> **Nikto note:** Most of the ~140 "backup file" entries are false positives — Nikto probes common backup filenames based on the hostname (`host.docker.internal`), most of which return 404. The 10 genuine findings are listed below.

### 2.3 Tool-Specific Strengths and Example Findings

**ZAP — Comprehensive web app scanning with authentication support**
- Performs full HTTP traffic analysis: headers, cookies, responses
- Best example finding: `Cross-Domain Misconfiguration` — `Access-Control-Allow-Origin: *` detected on `http://localhost:3000` (CWE-264). Allows any website to make cross-origin requests to the API.
- Second example: `CSP Header Not Set` on all pages — no XSS mitigation at the browser level.

**Nuclei — Fast template-based CVE detection**  
- Strength: scans thousands of templates in minutes, ideal for known vulnerability detection
- Found 0 results against Juice Shop v19 — confirms there are no currently-known unpatched CVEs
- Best used in CI/CD pipelines to catch newly-disclosed vulnerabilities in deployed services

**Nikto — Web server misconfiguration detection**
- Genuine findings from the scan:
  - Missing security headers: `Content-Security-Policy`, `Referrer-Policy`, `Strict-Transport-Security`, `Permissions-Policy`
  - `CORS: Access-Control-Allow-Origin: *` — overly permissive
  - `X-Frame-Options` deprecated (replaced by CSP `frame-ancestors`)
  - `/ftp/` directory publicly accessible and returns HTTP 200
  - `/public/` directory exposed
  - `/.htpasswd` file accessible — contains authorization information
  - `robots.txt` discloses `/ftp/` path (information leak)
- Best used for quick server-level configuration audits during deployment

**SQLmap — Deep SQL injection analysis**
- Confirmed SQL injection in 2 endpoints:
  1. `GET /rest/products/search?q=*` — Boolean-based blind injection (AND clause). Payload: `') AND 2864=2864 AND ('ougz' LIKE 'ougz`
  2. `POST /rest/user/login` — Boolean-based blind injection in JSON `email` parameter
- Database extracted: SQLite backend confirmed. Successfully dumped `SecurityAnswers` table (20 rows with hashed answers) and `PrivacyRequests` table.
- Best used for targeted SQL injection testing when SAST or DAST scans indicate database-related vulnerabilities

---

## Task 3: SAST vs DAST Correlation

### 3.1 Findings Summary

| Tool | Type | Findings |
|------|------|----------|
| Semgrep | SAST | 25 (7 ERROR, 18 WARNING) |
| ZAP | DAST | 11 |
| Nuclei | DAST | 0 |
| Nikto | DAST | ~10 real |
| SQLmap | DAST | 2 injection points + DB dump |

**Total SAST findings:** 25  
**Total DAST findings (combined):** ~23 unique issues

### 3.2 What Only SAST Found

| Vulnerability | Why DAST Misses It |
|---------------|-------------------|
| **Unquoted template variable (XSS)** in `dataErasureForm.hbs:21` | Requires source code inspection; DAST sees rendered output, not template logic |
| **Path traversal via `res.sendFile`** in `quarantineServer.ts:14` | Not triggered by automated crawling; needs specific crafted payload targeting known paths |
| **XSS via `subs` in `<script>` tag** in `videoHandler.ts:58` | Triggered only with specific subtitle file content; automated scanner won't exercise this flow |

**Why SAST finds these:** Static analysis reads every line of code regardless of execution path. It detects patterns like unquoted variables, unsanitized inputs to dangerous sinks, and insecure API usage without needing to execute the application.

### 3.3 What Only DAST Found

| Vulnerability | Why SAST Misses It |
|---------------|-------------------|
| **CSP header not set** (ZAP, Nikto) | This is a runtime/deployment configuration issue — no CSP header is set by the web server. Source code analysis cannot detect missing HTTP response headers unless explicitly configured to check them. |
| **CORS misconfiguration** (`Access-Control-Allow-Origin: *`) | A runtime header sent in HTTP responses. The policy may be set in middleware config files, not as an obvious code pattern |
| **`/ftp/` directory publicly accessible** (Nikto, ZAP) | Requires a live HTTP request to discover. SAST sees that directory listing is enabled in code, but cannot confirm which paths are actually accessible at runtime |

**Why DAST finds these:** Dynamic testing interacts with the running application over HTTP, observing actual response headers, accessible endpoints, and runtime behavior that static analysis cannot simulate.

### 3.4 Security Recommendations

1. **Enable Content Security Policy** — Add a strict CSP header to all responses to prevent XSS exploitation
2. **Restrict CORS policy** — Replace `Access-Control-Allow-Origin: *` with an explicit allowlist of trusted origins
3. **Disable directory listing** — Remove `serveIndex()` calls or restrict them to authenticated admin users
4. **Fix path traversal in `quarantineServer.ts`** — Validate and canonicalize file paths; use `path.resolve()` and check that the result stays within the allowed directory
5. **Parameterize all SQL queries** — Both confirmed SQLmap injection points indicate raw string interpolation in database queries; use ORM parameterized queries throughout
6. **Add missing security headers** — `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy` are all absent
7. **Validate redirect targets** — Implement an allowlist in `redirect.ts` to prevent open redirect abuse

### 3.5 SAST vs DAST: When to Use Each

| Approach | Best Phase | Strengths | Limitations |
|----------|-----------|-----------|-------------|
| **SAST (Semgrep)** | Development, pre-commit, PR checks | Catches code-level bugs early, no running app needed, fast feedback loop | Cannot see runtime config, deployment issues, or actual exploitability |
| **DAST (ZAP, Nikto, SQLmap)** | Staging, QA, pre-release | Tests real running behavior, finds config/header issues, confirms exploitability | Requires deployed app, misses code paths not exercised by crawling |

**Recommendation:** Use both in every DevSecOps pipeline. SAST in the inner loop (developer commits), DAST in the outer loop (staging environment). Neither alone provides complete coverage — Juice Shop demonstrates this clearly: SAST found code-level XSS patterns that DAST missed, while DAST confirmed SQL injection and found missing headers that SAST could not detect.
