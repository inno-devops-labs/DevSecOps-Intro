# Lab 5 — Security Analysis: SAST & DAST of OWASP Juice Shop

**Branch:** `feature/lab5`  
**Target:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — Static Application Security Testing with Semgrep

### 1.1 SAST Tool Effectiveness

Semgrep was run against the full Juice Shop v19.0.0 source tree using the `p/security-audit` and `p/owasp-top-ten` rule packs.

**Scan statistics:**

| Metric | Value |
|--------|-------|
| Files scanned | 1,014 |
| Rules executed | 140 (674 total loaded, filtered to relevant) |
| Total findings | 25 |
| Blocking findings | 25 |
| Languages covered | TypeScript, JavaScript, JSON, YAML, HTML, Dockerfile, Bash |
| Files skipped (>1MB) | 8 |
| Files skipped (.semgrepignore) | 139 |

**Vulnerability types detected:**

Semgrep detected six distinct vulnerability categories across the codebase. SQL injection patterns (via Sequelize raw queries) were the most prevalent at 6 instances and the highest severity. Directory listing misconfigurations appeared 4 times in `server.ts`. Unquoted template variables vulnerable to XSS appeared in 4 HTML/Handlebars templates. Additional findings included a hardcoded JWT secret, raw HTML injection in the chatbot route, unsafe `res.sendFile` usage in 4 file-serving routes, an open redirect, code string concatenation enabling injection, and script-tag injection in the video handler.

### 1.2 Critical Vulnerability Analysis — Top 5 Findings

**1. SQL Injection via Sequelize Raw Query — Production Login Route**

| Field | Detail |
|-------|--------|
| Rule | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| File | `/src/routes/login.ts` |
| Line | 34 |
| Severity | ERROR |
| Description | User-controlled input passed directly into a Sequelize query without parameterization. An attacker can manipulate the SQL to bypass authentication entirely or extract database contents. This is the primary authentication bypass vector in Juice Shop. |

**2. SQL Injection via Sequelize Raw Query — Product Search Route**

| Field | Detail |
|-------|--------|
| Rule | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| File | `/src/routes/search.ts` |
| Line | 23 |
| Severity | ERROR |
| Description | The search parameter `q` is concatenated directly into a Sequelize query. SQLmap confirmed exploitation of this endpoint with a boolean-based blind injection payload: `') AND 3692=3692 AND ('DEov' LIKE 'DEov`. |

**3. Code String Concatenation — Arbitrary Code Execution Risk**

| Field | Detail |
|-------|--------|
| Rule | `javascript.lang.security.audit.code-string-concat.code-string-concat` |
| File | `/src/routes/userProfile.ts` |
| Line | 62 |
| Severity | ERROR |
| Description | User-controlled input is concatenated into a string that is subsequently evaluated as code. This pattern enables remote code execution if an attacker can control the concatenated value. |

**4. Hardcoded JWT Secret**

| Field | Detail |
|-------|--------|
| Rule | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` |
| File | `/src/lib/insecurity.ts` |
| Line | 56 |
| Severity | WARNING |
| Description | The RSA private key used to sign JWTs is hardcoded in the source file. Any attacker with access to the source can forge arbitrary JWT tokens for any user, including admin. |

**5. SQL Injection in Code Fix Challenge Files**

| Field | Detail |
|-------|--------|
| Rule | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| File | `/src/data/static/codefixes/dbSchemaChallenge_1.ts`, `dbSchemaChallenge_3.ts`, `unionSqlInjectionChallenge_1.ts`, `unionSqlInjectionChallenge_3.ts` |
| Lines | 5, 11, 6, 10 |
| Severity | ERROR |
| Description | Four additional SQL injection instances exist in the challenge codefix files. While these are intentional for the educational challenge, Semgrep correctly flags them — demonstrating its ability to identify vulnerable patterns regardless of intent, which is the expected behavior in a CI/CD pipeline. |

---

## Task 2 — Dynamic Application Security Testing with Multiple Tools

### 2.1 Authenticated vs Unauthenticated ZAP Scanning

**URL Discovery Comparison:**

| Scan Type | URLs Discovered | Spider Method |
|-----------|----------------|---------------|
| Unauthenticated baseline | 95 | Traditional spider only |
| Authenticated (spider) | 58 | Traditional spider with admin session |
| Authenticated (AJAX spider) | 567 | JavaScript-aware AJAX spider |
| **Total authenticated** | **625** | Combined |

The authenticated scan discovered **6.6× more URLs** than the unauthenticated baseline (625 vs 95). The AJAX spider alone found 567 URLs by executing Angular JavaScript and navigating the SPA dynamically, which the traditional spider cannot do.

**Examples of authenticated-only endpoints discovered:**

- `/rest/admin/application-configuration` — exposes full application configuration including feature flags
- `/rest/user/whoami` — returns current authenticated user details
- `/api/Users` — full user management API accessible only when logged in
- `/rest/basket/:id` — user-specific basket contents
- `/rest/order-history` — purchase history accessible after authentication
- `/profile` — user profile management page
- `/rest/memories` — private user photo memories endpoint

**Why authenticated scanning matters:**

Unauthenticated scans only see the attack surface available to anonymous users — login forms, public product pages, and static assets. The majority of a web application's functionality and its most sensitive operations (account management, admin panels, payment processing) sit behind authentication. Without authenticating, a scanner misses the endpoints most likely to contain authorization flaws, IDOR vulnerabilities, and business logic issues. In this case, authentication expanded coverage by over 500 additional URLs and enabled the active scanner to test admin-only endpoints that represent the highest business risk.

### 2.2 Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|------|----------|--------------------|---------------|
| ZAP (authenticated) | 15 alerts | 1 High, 5 Medium, 4 Low | Comprehensive web app scanning with authentication support; covers headers, injection, session management |
| ZAP (unauthenticated) | 13 alerts | 0 High, 2 Medium, 6 Low | Quick baseline scan of publicly accessible endpoints |
| Nuclei | 25 matches | 1 Medium, 23 Info, 1 Unknown | Fast template-based known-CVE detection and technology fingerprinting |
| Nikto | 84 findings | Mixed (server-level) | Web server misconfiguration and backup file detection |
| SQLmap | 1 confirmed SQLi | Critical (confirmed exploitation) | Deep SQL injection confirmation and data extraction |

### 2.3 Tool-Specific Strengths

**ZAP — Comprehensive Authenticated Web Application Scanning**

ZAP is the most versatile DAST tool in this comparison, uniquely supporting session management and authenticated scanning. Its active scanner probed every discovered endpoint with attack payloads after establishing an admin session.

Key findings from ZAP:
- **SQL Injection (High)** — Active scanner confirmed injectable parameter in the application, corroborating both the Semgrep SAST finding and the SQLmap confirmation.
- **Missing Content Security Policy (Medium/Systemic)** — Detected across all pages, enabling unrestricted script execution and XSS exploitation. This is a deployment-level finding that SAST cannot detect.
- **HTTP Only Site (Medium)** — The application serves entirely over HTTP with no HTTPS enforcement, exposing all traffic including credentials to interception.
- **Missing Anti-Clickjacking Header (Medium)** — The `X-Frame-Options` header is absent on 3 endpoints, enabling iframe-based UI redressing attacks.
- **Session ID in URL Rewrite (Medium/Systemic)** — Session tokens appearing in URLs risk leakage via Referer headers and browser history.
- **Cross-Domain Misconfiguration (Medium/Systemic)** — The `Access-Control-Allow-Origin: *` header allows any origin to make credentialed cross-domain requests.

**Nuclei — Fast Template-Based Fingerprinting and Known Vulnerability Detection**

Nuclei excels at rapid scanning using community-maintained templates for known CVEs and technology fingerprinting. It completed its scan in under 3 minutes.

Key findings from Nuclei:
- **Prometheus Metrics Exposed (Medium)** — The `/metrics` endpoint is publicly accessible without authentication, leaking detailed internal application telemetry including request counts, user counts, wallet balances, and HTTP error rate breakdowns. This constitutes a significant information disclosure.
- **Public Swagger API Detected (Info)** — The API documentation endpoint is publicly accessible, giving attackers a complete map of all API endpoints, parameters, and expected responses — dramatically reducing reconnaissance effort.
- **HTTP Missing Security Headers (Info, 8 instances)** — Multiple security headers absent across different endpoints: `X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-Permitted-Cross-Domain-Policies`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`.
- **Deprecated Feature-Policy Header (Info)** — The application uses the deprecated `Feature-Policy` header instead of the modern `Permissions-Policy` replacement.
- **OWASP Juice Shop Fingerprint (Info)** — Nuclei positively identified the application as OWASP Juice Shop via template matching, demonstrating its technology fingerprinting capability.

**Nikto — Web Server Misconfiguration and Backup File Detection**

Nikto specializes in server-level issues and is particularly effective at enumerating potentially dangerous files and checking server configuration. It reported 84 findings in 158 seconds.

Key findings from Nikto:
- **Accessible `/ftp/` Directory (Notable)** — The robots.txt entry for `/ftp/` returns HTTP 200 rather than a redirect or 403. This directory contains sensitive backup files including `package-lock.json.bak` and easter egg files.
- **Missing Security Headers (4 findings)** — Nikto independently confirmed the absence of `Permissions-Policy`, `Strict-Transport-Security`, `Content-Security-Policy`, and `Referrer-Policy` headers.
- **Backup/Certificate File Probing (70+ findings)** — Nikto probed for over 70 common backup and certificate file patterns (`.tar`, `.bak`, `.pem`, `.war`, `.jks`, `.egg`, `.alz`, etc.) on common filenames (`backup`, `database`, `dump`, `archive`, `localhost`, `127.0.0.1`, `site`). While most are false positives for Juice Shop, this demonstrates Nikto's exhaustive server enumeration capability that is valuable for detecting accidentally exposed sensitive files.
- **Overly Permissive CORS (`Access-Control-Allow-Origin: *`)** — Confirmed independently, corroborating ZAP's finding.
- **`x-recruiting` Header Disclosure** — An unusual custom header reveals the application's job board endpoint, an information disclosure that could aid social engineering.
- **`.htpasswd` File Detected** — A potentially sensitive authorization file was identified.

**SQLmap — Deep SQL Injection Confirmation and Data Extraction**

SQLmap is the definitive tool for confirming and exploiting SQL injection. Unlike ZAP which reports suspected injection, SQLmap proves it with a working payload and can extract actual data.

Key findings from SQLmap:
- **Confirmed Boolean-Based Blind SQL Injection in Search Endpoint** — SQLmap confirmed injectable parameter `q` in `GET /rest/products/search?q=*` with the payload `') AND 3692=3692 AND ('DEov' LIKE 'DEov`. The backend DBMS was positively identified as **SQLite**. This transforms a suspected vulnerability into a proven, exploitable finding.
- **500 Error Pattern** — SQLmap detected 10 HTTP 500 errors during the scan, indicating the application crashes on certain malformed inputs — a sign of poor error handling that aids blind injection techniques by providing distinguishable response states.
- **Login Endpoint Resistance** — The JSON POST body format of the login endpoint (`{"email":"*","password":"test"}`) resisted standard SQLmap parameter detection. The login SQLi confirmed by ZAP's active scanner would require custom tamper scripts or manual exploitation to fully demonstrate with SQLmap.

---

## Task 3 — SAST/DAST Correlation and Security Assessment

### 3.1 SAST vs DAST Comparison

**Finding Counts:**

| Approach | Tool | Findings |
|----------|------|----------|
| SAST | Semgrep | 25 |
| DAST | ZAP (authenticated) | 15 |
| DAST | Nuclei | 25 |
| DAST | Nikto | 84 |
| DAST | SQLmap | 1 confirmed SQLi |
| **Total DAST** | | **125** |

**Vulnerability types found ONLY by SAST:**

1. **Hardcoded JWT secret in source code** (`/src/lib/insecurity.ts:56`) — Semgrep detected the RSA private key directly in source. DAST tools interact with the running application and cannot inspect source files; they would only detect the symptom (forged token acceptance) not the root cause.

2. **Code string concatenation leading to code execution** (`/src/routes/userProfile.ts:62`) — This pattern requires reading source code to identify. A DAST scanner might detect the resulting behavior if it produces an observable error, but Semgrep pinpoints the exact vulnerable line before deployment.

3. **Unsafe `res.sendFile` without path validation** (`/src/routes/fileServer.ts:33`, `keyServer.ts:14`, `logfileServer.ts:14`, `quarantineServer.ts:14`) — SAST identified four file-serving routes using `res.sendFile` with potentially unsanitized paths. DAST could detect path traversal only if it successfully exploits it; SAST catches the pattern regardless.

**Vulnerability types found ONLY by DAST:**

1. **Missing security headers (CSP, HSTS, Referrer-Policy, Permissions-Policy)** — These are deployment and runtime configuration issues. The headers are set (or not set) by the running server, not determinable from source code. ZAP, Nuclei, and Nikto all independently confirmed their absence.

2. **Exposed Prometheus metrics endpoint** (`/metrics`) — Nuclei discovered this unauthenticated telemetry endpoint leaking internal application statistics. This is a runtime deployment configuration issue — the endpoint exists and is accessible; source analysis would not reveal whether it is protected without also analysing the server configuration.

3. **Session ID in URL rewrite and HTTP-only site** — These are runtime session management and transport security behaviors observable only when the application is running and handling real requests.

**Why each approach finds different things:**

SAST analyzes source code statically without executing it. This makes it uniquely capable of finding vulnerabilities in code paths that may never be triggered at runtime, identifying secrets embedded in code before they are deployed, and pinpointing the exact file and line responsible for a vulnerability — providing developers with actionable fix locations early in the development cycle. However, SAST cannot observe how the application behaves under real network conditions, how the server is configured, or whether deployed security controls are actually functioning.

DAST interacts with the running application as an attacker would. This means it finds issues that only manifest at runtime: misconfigured HTTP headers, accessible endpoints that should be restricted, actual exploitability of injection flaws (not just their presence in code), and behavioral issues like session management weaknesses. However, DAST is blind to the underlying code — it can confirm that SQL injection is exploitable on an endpoint but cannot tell the developer which line of code is responsible.

The two approaches are complementary rather than competitive. SAST provides early-stage, developer-facing feedback with precise code locations, while DAST provides deployment-stage confirmation of real-world exploitability. A complete DevSecOps pipeline requires both.

### 3.2 Security Recommendations

**Critical — Address Immediately:**

1. **Parameterize all database queries** — Replace raw Sequelize string concatenation in `login.ts:34` and `search.ts:23` with parameterized queries or ORM methods that prevent SQL injection. This eliminates the highest-severity confirmed vulnerability.

2. **Remove hardcoded JWT secret** — Move the RSA private key from `insecurity.ts` to an environment variable or secrets manager (HashiCorp Vault, AWS Secrets Manager). Rotate the current key immediately as it is baked into the public Docker image.

3. **Enforce HTTPS** — Add `Strict-Transport-Security` header and redirect all HTTP traffic to HTTPS. Credentials submitted over HTTP are trivially interceptable.

**High Priority — Address Within Sprint:**

4. **Implement Content Security Policy** — Add a restrictive CSP header to prevent XSS exploitation. The absence of CSP was confirmed by ZAP, Nuclei, and Nikto independently.

5. **Restrict the `/metrics` endpoint** — The Prometheus metrics endpoint leaks internal application telemetry. Restrict it to internal networks or require authentication.

6. **Disable or restrict the `/ftp/` directory** — Public access to backup files represents unnecessary information exposure.

**Medium Priority — Architectural Improvements:**

7. **Quote all template variables** — Fix unquoted attribute variables in `navbar.component.html:17`, `purchase-basket.component.html:15`, `search-result.component.html:40`, and `dataErasureForm.hbs:21` to prevent attribute injection XSS.

8. **Validate paths in file-serving routes** — Add path traversal protection to `fileServer.ts`, `keyServer.ts`, `logfileServer.ts`, and `quarantineServer.ts` before passing user input to `res.sendFile`.

9. **Add anti-clickjacking protection** — Implement `Content-Security-Policy: frame-ancestors 'self'` to replace the deprecated `X-Frame-Options` header and prevent UI redressing attacks.

---

## Appendix — Tool Commands Reference

```bash
# SAST
docker run --rm -v "$(pwd)/labs/lab5/semgrep/juice-shop:/src" \
  -v "$(pwd)/labs/lab5/semgrep:/output" semgrep/semgrep:latest \
  semgrep --config=p/security-audit --config=p/owasp-top-ten \
  --json --output=/output/semgrep-results.json /src

# ZAP unauthenticated
docker run --rm --network host -v "$(pwd)/labs/lab5/zap:/zap/wrk/:rw" \
  zaproxy/zap-stable:latest zap-baseline.py -t http://localhost:3000 \
  -r report-noauth.html -J zap-report-noauth.json

# ZAP authenticated
docker run --rm --network host -v "$(pwd)/labs/lab5:/zap/wrk/:rw" \
  zaproxy/zap-stable:latest zap.sh -cmd -port 8090 -autorun /zap/wrk/scripts/zap-auth.yaml

# Nuclei
docker run --rm --network host -v "$(pwd)/labs/lab5/nuclei:/app" \
  projectdiscovery/nuclei:latest \
  -ut -u http://localhost:3000 \
  -jsonl -o /app/nuclei-results.json

# Nikto
docker run --rm --network host -v "$(pwd)/labs/lab5/nikto:/tmp" \
  alpine/nikto -h http://localhost:3000 -o /tmp/nikto-results.txt

# SQLmap
docker run --rm --network host \
  -v "$(pwd)/labs/lab5/sqlmap:/output" secsi/sqlmap \
  -u "http://localhost:3000/rest/products/search?q=*" \
  --dbms=sqlite --batch --level=3 --risk=2 --technique=B \
  --threads=5 --output-dir=/output
```