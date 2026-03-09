# Lab 5 — Security Analysis: SAST & DAST of OWASP Juice Shop

## Task 1 — Static Application Security Testing with Semgrep

### 1 SAST Tool Effectiveness

**Vulnerability types detected:**

Semgrep identified 7 categories of security flaws in the examined codebase, mainly centered on web app security concerns in JavaScript/TypeScript, Express.js, and Sequelize. These results are grouped according to typical vulnerability categories (e.g., drawn from CWE and OWASP mentions in the scan output).

| Metric | Value |
|--------|-------|
| Files scanned | 1,014 |
| Total findings | 25 |

### 1.2 Critical Vulnerability Analysis — Top 5 Findings

**1. SQL Injection through Sequelize Raw Query — Production Login Route**

| Field | Detail |
|-------|--------|
| Rule | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| File | `/src/routes/login.ts` |
| Line | 34 |
| Severity | ERROR |

**2. SQL Injection through Sequelize Raw Query — Product Search Route**

| Field | Detail |
|-------|--------|
| Rule | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| File | `/src/routes/search.ts` |
| Line | 23 |
| Severity | ERROR |

**3. Code String Concatenation — Risk of Arbitrary Code Execution**

| Field | Detail |
|-------|--------|
| Rule | `javascript.lang.security.audit.code-string-concat.code-string-concat` |
| File | `/src/routes/userProfile.ts` |
| Line | 62 |
| Severity | ERROR |

**4. Hardcoded JWT Secret**

| Field | Detail |
|-------|--------|
| Rule | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` |
| File | `/src/lib/insecurity.ts` |
| Line | 56 |
| Severity | WARNING |

**5. SQL Injection in Code Fix Challenge Files**

| Field | Detail |
|-------|--------|
| Rule | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| File | `/src/data/static/codefixes/dbSchemaChallenge_1.ts`, `dbSchemaChallenge_3.ts`, `unionSqlInjectionChallenge_1.ts`, `unionSqlInjectionChallenge_3.ts` |
| Lines | 5, 11, 6, 10 |
| Severity | ERROR |

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

The authenticated scan uncovered **6.6× more URLs** compared to the unauthenticated baseline (625 versus 95). The AJAX spider by itself identified 567 URLs by running Angular JavaScript and dynamically exploring the single-page application, something the traditional spider is unable to achieve.

**Examples of authenticated-only endpoints discovered:**

- `/rest/admin/application-configuration` — reveals complete app settings including feature toggles
- `/rest/user/whoami` — provides details of the currently logged-in user
- `/api/Users` — complete user administration API available only post-login
- `/rest/basket/:id` — contents of user-specific shopping basket
- `/rest/order-history` — access to purchase records after logging in
- `/profile` — page for managing user profiles
- `/rest/memories` — endpoint for private user photo recollections

**Why authenticated scanning matters:**

Scans without authentication only access the surface exposed to anonymous visitors — such as login pages, public item listings, and static resources. Most of a web app's features and sensitive functions (like account handling, admin interfaces, and payments) are protected by login requirements. Without logging in, a scanner overlooks the areas prone to authorization errors, insecure direct object references, and logic flaws. Here, authentication boosted coverage by more than 500 extra URLs and allowed active scanning of admin-exclusive endpoints posing the greatest risk to the business.

### 2.2 Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|------|----------|--------------------|---------------|
| ZAP (authenticated) | 15 alerts | 1 High, 5 Medium, 4 Low | Thorough web application assessment with login capabilities; addresses headers, injections, and session handling |
| ZAP (unauthenticated) | 13 alerts | 0 High, 2 Medium, 6 Low | Rapid initial evaluation of openly available endpoints |
| Nuclei | 25 matches | 1 Medium, 23 Info, 1 Unknown | Quick pattern-based identification of known vulnerabilities and tech stack profiling |
| Nikto | 84 findings | Mixed (server-level) | Detection of web server setup errors and leftover files |
| SQLmap | 1 confirmed SQLi | Critical (confirmed exploitation) | In-depth verification of SQL injections and data retrieval |

### 2.3 Tool-Specific Strengths

**ZAP — Comprehensive Authenticated Web Application Scanning**

ZAP stands out as the most adaptable DAST tool here, with unique features for managing sessions and performing scans while authenticated. Its active scanning component tested all found endpoints with attack vectors after setting up an admin session.

Key findings from ZAP:
- **SQL Injection (High)** — The active scanner verified an injectable parameter within the app, aligning with the Semgrep SAST result and SQLmap's validation.
- **Missing Content Security Policy (Medium/Systemic)** — Identified on every page, allowing unlimited script runs and XSS attacks. This deployment issue is beyond SAST's scope.
- **HTTP Only Site (Medium)** — App operates solely over HTTP without HTTPS mandates, leaving all data, including logins, vulnerable to eavesdropping.
- **Missing Anti-Clickjacking Header (Medium)** — No `X-Frame-Options` on 3 endpoints, permitting iframe-driven clickjacking.
- **Session ID in URL Rewrite (Medium/Systemic)** — Session identifiers in URLs could leak through Referer or history logs.
- **Cross-Domain Misconfiguration (Medium/Systemic)** — `Access-Control-Allow-Origin: *` permits any site to send credentialed requests across domains.

**Nuclei — Fast Template-Based Fingerprinting and Known Vulnerability Detection**

Nuclei shines in swift assessments via community-curated patterns for recognized CVEs and stack identification. It finished its run in less than 3 minutes.

Key findings from Nuclei:
- **Prometheus Metrics Exposed (Medium)** — `/metrics` is open without login, exposing internal metrics like request totals, user numbers, wallet amounts, and error rates — a major data leak.
- **Public Swagger API Detected (Info)** — API docs endpoint is openly available, offering attackers a full blueprint of APIs, params, and responses — easing initial scouting.
- **HTTP Missing Security Headers (Info, 8 instances)** — Various endpoints lack headers like `X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-Permitted-Cross-Domain-Policies`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`.
- **Deprecated Feature-Policy Header (Info)** — App employs outdated `Feature-Policy` rather than current `Permissions-Policy`.
- **OWASP Juice Shop Fingerprint (Info)** — Nuclei confirmed the app as OWASP Juice Shop through pattern matching, showcasing its identification prowess.

**Nikto — Web Server Misconfiguration and Backup File Detection**

Nikto focuses on server-side problems and excels at listing risky files while verifying configs. It logged 84 issues in 158 seconds.

Key findings from Nikto:
- **Accessible `/ftp/` Directory (Notable)** — robots.txt's `/ftp/` entry yields 200 OK instead of denial. This folder holds backups like `package-lock.json.bak` and hidden files.
- **Missing Security Headers (4 findings)** — Nikto verified lacks in `Permissions-Policy`, `Strict-Transport-Security`, `Content-Security-Policy`, and `Referrer-Policy`.
- **Backup/Certificate File Probing (70+ findings)** — Checked numerous patterns (`.tar`, `.bak`, `.pem`, etc.) on files like `backup`, `database`. Mostly negatives for Juice Shop, but highlights Nikto's thorough probing for exposed files.
- **Overly Permissive CORS (`Access-Control-Allow-Origin: *`)** — Validated separately, matching ZAP's observation.
- **`x-recruiting` Header Disclosure** — Custom header exposes job board link, potentially useful for social attacks.
- **`.htpasswd` File Detected** — Spotted a possible auth file with sensitivity.

**SQLmap — Deep SQL Injection Confirmation and Data Extraction**

SQLmap is the go-to for validating and leveraging SQL injections. While ZAP flags potentials, SQLmap demonstrates with exploits and data pulls.

Key findings from SQLmap:
- **Confirmed Boolean-Based Blind SQL Injection in Search Endpoint** — Verified `q` param in `GET /rest/products/search?q=*` injectable via `') AND 3692=3692 AND ('DEov' LIKE 'DEov`. DBMS confirmed as **SQLite**. Turns suspicion into proven exploit.
- **500 Error Pattern** — Noted 10 server errors in scan, showing app failures on bad inputs — helping blind injection by response differences.
- **Login Endpoint Resistance** — Login's JSON POST (`{"email":"*","password":"test"}`) evaded standard detection. ZAP-flagged login SQLi needs custom tweaks or manual work for SQLmap proof.

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

1. **Hardcoded JWT secret in source code** (`/src/lib/insecurity.ts:56`) — Semgrep spotted the RSA key in code. DAST engages the live app and misses source inspection; it might catch forged tokens but not the cause.

2. **Code string concatenation leading to code execution** (`/src/routes/userProfile.ts:62`) — Needs code review to spot. DAST could see effects if errors show, but Semgrep locates the precise issue pre-deployment.

3. **Unsafe `res.sendFile` without path validation** (`/src/routes/fileServer.ts:33`, `keyServer.ts:14`, `logfileServer.ts:14`, `quarantineServer.ts:14`) — SAST flagged four routes with risky paths. DAST detects traversal only on success; SAST catches regardless.

**Vulnerability types found ONLY by DAST:**

1. **Missing security headers (CSP, HSTS, Referrer-Policy, Permissions-Policy)** — Runtime and config matters. Headers are handled by the live server, not code-detectable. ZAP, Nuclei, Nikto all noted absences.

2. **Exposed Prometheus metrics endpoint** (`/metrics`) — Nuclei found this open telemetry leak. It's a live config issue — endpoint is reachable; source alone doesn't show protection.

3. **Session ID in URL rewrite and HTTP-only site** — Runtime behaviors in sessions and transport, visible only during active requests.

**Why each approach finds different things:**

SAST examines code without running it, enabling detection of issues in unused paths, embedded secrets pre-deployment, and exact code spots for fixes early on. But it misses real-world network behaviors, server setups, or active controls.

DAST simulates attacks on the live app, uncovering runtime issues like header misconfigs, unprotected endpoints, true injection exploits, and session flaws. Yet it ignores code internals — it confirms SQLi exploitability but not the faulty line.

They complement each other: SAST offers early, precise dev insights; DAST verifies real exploits at deployment. Full security needs both in the pipeline.

### 3.2 Security Recommendations

**Critical — Address Immediately:**

1. **Parameterize all database queries** — Swap raw string joins in `login.ts:34` and `search.ts:23` for safe params or ORM to block SQLi. Fixes the top confirmed threat.

2. **Remove hardcoded JWT secret** — Shift RSA key from `insecurity.ts` to env vars or secrets service (e.g., Vault, AWS). Change the key now, as it's in public images.

3. **Enforce HTTPS** — Include `Strict-Transport-Security` and redirect HTTP to HTTPS. Plain HTTP exposes creds to capture.

**High Priority — Address Within Sprint:**

4. **Implement Content Security Policy** — Apply strict CSP to stop XSS. Lack confirmed by ZAP, Nuclei, Nikto.

5. **Restrict the `/metrics` endpoint** — Prometheus leaks internals; limit to internal access or require auth.

6. **Disable or restrict the `/ftp/` directory** — Open backups pose info risks.

**Medium Priority — Architectural Improvements:**

7. **Quote all template variables** — Correct unquoted attrs in `navbar.component.html:17`, `purchase-basket.component.html:15`, `search-result.component.html:40`, `dataErasureForm.hbs:21` to avoid XSS via attributes.

8. **Validate paths in file-serving routes** — Add traversal safeguards in `fileServer.ts`, `keyServer.ts`, `logfileServer.ts`, `quarantineServer.ts` before `res.sendFile`.

9. **Add anti-clickjacking protection** — Use `Content-Security-Policy: frame-ancestors 'self'` to supersede old `X-Frame-Options` and block redressing.

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