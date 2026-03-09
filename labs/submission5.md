# Lab 5 Submission — SAST & DAST Security Analysis

**Student:** Sarmat  
**Date:** March 9, 2026

---

## Task 1 — Static Application Security Testing (SAST) with Semgrep

### SAST Tool Effectiveness

Semgrep successfully performed static code analysis on the OWASP Juice Shop v19.0.0 codebase using security-audit and OWASP Top 10 rulesets.

**Scan Coverage:**
- Files scanned: 1,014 files tracked by git
- Rules executed: 140 security rules
- Total findings: 25 vulnerabilities (all blocking severity)
- Code parsed: ~99.9% successfully parsed
- Skipped: 8 files >1MB, 139 files matching .semgrepignore

**Vulnerability Types Detected:**
Semgrep identified code-level security issues including:
- SQL Injection patterns (Sequelize ORM misuse)
- Hardcoded credentials and secrets
- Cross-Site Scripting (XSS) vulnerabilities
- Path Traversal issues
- Code Injection (eval usage)
- Open Redirect vulnerabilities
- Directory listing exposure

### Critical Vulnerability Analysis

#### Top 5 Most Critical Findings:

1. **SQL Injection - Login Endpoint**
   - Type: SQL Injection (CWE-89)
   - File: `/src/routes/login.ts`
   - Line: 34
   - Severity: ERROR (High)
   - Description: Sequelize query tainted by user input without parameterization
   - OWASP: A03:2021 - Injection

2. **SQL Injection - Search Endpoint**
   - Type: SQL Injection (CWE-89)
   - File: `/src/routes/search.ts`
   - Line: 23
   - Severity: ERROR (High)
   - Description: User-controlled search parameter directly concatenated into SQL query
   - OWASP: A03:2021 - Injection

3. **Code Injection - User Profile**
   - Type: Eval Injection (CWE-95)
   - File: `/src/routes/userProfile.ts`
   - Line: 62
   - Severity: ERROR (High)
   - Description: User data flows to `eval()` function enabling arbitrary code execution
   - OWASP: A03:2021 - Injection

4. **Hardcoded JWT Secret**
   - Type: Hard-coded Credentials (CWE-798)
   - File: `/src/lib/insecurity.ts`
   - Line: 56
   - Severity: WARNING (Medium-High)
   - Description: JWT signing secret hardcoded in source code
   - OWASP: A07:2021 - Identification and Authentication Failures

5. **Path Traversal - File Server**
   - Type: External Control of File Name (CWE-73)
   - File: `/src/routes/fileServer.ts`
   - Line: 33
   - Severity: WARNING (Medium)
   - Description: User input passed to `res.sendFile()` without validation
   - OWASP: A04:2021 - Insecure Design

---

## Task 2 — Dynamic Application Security Testing (DAST)

### Authenticated vs Unauthenticated Scanning

**ZAP Scan Comparison:**


**URL Discovery:**
- Unauthenticated scan: 15 unique URLs discovered
- Authenticated scan: 25 unique URLs discovered  
- Difference: +10 URLs (67% increase with authentication)

**Spider Results (from ZAP automation log):**
- Standard Spider: 112 URLs found
- AJAX Spider: 890 URLs found (8x more than standard spider)
- Total authenticated coverage: 1,002 URLs explored

**Alerts by Severity:**

Unauthenticated Scan:
- High (risk-3): 1 alert
- Medium (risk-2): 7 alerts
- Low (risk-1): 20 alerts
- Informational (risk-0): 22 alerts
- Total: 50 alerts

Authenticated Scan:
- High (risk-3): 1 alert
- Medium (risk-2): 13 alerts
- Low (risk-1): 14 alerts
- Informational (risk-0): 41 alerts
- Total: 69 alerts

**Key Authenticated Endpoints Discovered:**
- `/rest/admin/application-configuration` - Admin configuration API
- Various user-specific endpoints (basket, orders, profile)
- Payment and checkout flows
- User management endpoints

**Why Authenticated Scanning Matters:**

1. **Expanded Attack Surface**: Authenticated scanning revealed 67% more unique endpoints, including admin-only APIs that are invisible to unauthenticated users.

2. **Business Logic Vulnerabilities**: Many security issues only appear in authenticated contexts (e.g., privilege escalation, insecure direct object references).

3. **AJAX Discovery**: The AJAX spider found 8x more URLs than standard spidering by executing JavaScript, revealing dynamic endpoints loaded by the frontend.

4. **Real-World Coverage**: Attackers with stolen credentials or session tokens can access authenticated areas, making this testing critical for comprehensive security assessment.

### Tool Comparison Matrix

| Tool | Total Findings | Severity Breakdown | Best Use Case |
|------|---------------|-------------------|---------------|
| **ZAP (Auth)** | 69 alerts | High: 1, Med: 13, Low: 14, Info: 41 | Comprehensive web app scanning with authentication support, AJAX discovery |
| **Nuclei** | 8 findings | High: 1, Med: 4, Info: 3 | Fast template-based scanning for known vulnerabilities and misconfigurations |
| **Nikto** | 12 findings | Server issues: 12 | Web server misconfiguration and information disclosure |
| **SQLmap** | 1 vulnerability | SQL Injection: 1 (search endpoint) | Deep SQL injection analysis and database exploitation |

### Tool-Specific Strengths

#### OWASP ZAP
**Strengths:**
- Comprehensive scanning with integrated spider, passive, and active scanners
- Authentication framework supports complex login flows (JSON-based, cookie sessions)
- AJAX spider discovers JavaScript-rendered content (8x more URLs)
- Detailed HTML and JSON reports with remediation guidance

**Example Findings:**
- Cross-Domain JavaScript Source File Inclusion (5 instances)
- Content Security Policy (CSP) Header Not Set (5 instances)
- Cross-Domain Misconfiguration (5 instances)

#### Nuclei
**Strengths:**
- Extremely fast template-based scanning (completes in seconds)
- Community-driven template library with 10,000+ templates
- Low false-positive rate with signature-based detection
- Ideal for CI/CD integration and quick security checks

**Example Findings:**
- **Weak JWT Secret** (High): JWT implementation may use weak or predictable secrets
- **CORS Misconfiguration** (Medium): Access-Control-Allow-Origin set to wildcard (*)
- **Exposed FTP Directory** (Medium): `/ftp/` directory accessible without authentication
- **Backup File Exposure** (Medium): Backup files like `package.json.bak` accessible
- **Missing Security Headers** (Info): CSP, X-Frame-Options headers not configured
- **Technology Detection** (Info): OWASP Juice Shop fingerprint detected

#### Nikto
**Strengths:**
- Specialized in web server security assessment
- Detects server misconfigurations and information leaks
- Identifies interesting directories and files
- Fast execution (~83 seconds)

**Example Findings:**
- Server leaks inodes via ETags
- Directory `/ftp/` accessible (information disclosure)
- Uncommon headers detected: `x-recruiting`, `feature-policy`
- robots.txt contains sensitive directory listings

#### SQLmap
**Strengths:**
- Most advanced SQL injection testing tool
- Automatic database fingerprinting (detected SQLite)
- Supports complex injection techniques (boolean-based, time-based blind)
- Can extract entire databases after confirming vulnerability

**Example Finding:**
- **Search Endpoint SQL Injection**:
  - URL: `http://localhost:3000/rest/products/search?q=*`
  - Technique: Boolean-based blind injection
  - Payload: `') AND 1210=1210 AND ('qqsk' LIKE 'qqsk`
  - Database: SQLite confirmed
  - Impact: Full database access possible

---

## Task 3 — SAST/DAST Correlation and Security Assessment

### SAST vs DAST Comparison

**Total Findings:**
- SAST (Semgrep): 25 code-level vulnerabilities
- DAST (Combined): 90 runtime findings
  - ZAP: 69 alerts
  - Nikto: 12 findings
  - Nuclei: 8 findings
  - SQLmap: 1 confirmed SQL injection

### Vulnerability Types Found ONLY by SAST

1. **Hardcoded Secrets**
   - JWT signing keys embedded in source code
   - Cannot be detected by runtime testing without source access

2. **Code Injection Patterns**
   - `eval()` usage with user input in userProfile.ts
   - Requires code analysis to identify dangerous function usage

3. **Insecure Cryptographic Patterns**
   - Weak algorithm usage or improper implementation
   - Static analysis detects patterns before runtime

### Vulnerability Types Found ONLY by DAST

1. **Missing Security Headers**
   - Content-Security-Policy not set
   - X-Frame-Options, HSTS headers missing
   - Only detectable by inspecting HTTP responses

2. **Server Configuration Issues**
   - Directory listing enabled
   - Information disclosure via server headers
   - Requires live server interaction

3. **Session Management Flaws**
   - Cookie attributes (HttpOnly, Secure, SameSite)
   - Session fixation vulnerabilities
   - Runtime behavior analysis required

### Why Each Approach Finds Different Things

**SAST (Static Analysis):**
- Analyzes source code without execution
- Finds vulnerabilities in code logic and patterns
- Detects issues before deployment
- Cannot assess runtime configuration or deployment environment
- May produce false positives without runtime context

**DAST (Dynamic Analysis):**
- Tests running application like an attacker would
- Discovers configuration and deployment issues
- Validates exploitability of vulnerabilities
- Cannot see code logic or hardcoded secrets
- Limited to accessible attack surface

**Correlation Example:**
- SAST found SQL injection pattern in `/src/routes/search.ts` (line 23)
- DAST (SQLmap) confirmed the vulnerability is exploitable at runtime
- SAST identified the root cause, DAST proved real-world impact

### Security Recommendations

1. **Implement Both SAST and DAST in CI/CD Pipeline**
   - SAST: Run on every commit/PR (fast feedback)
   - DAST: Run on staging deployments (pre-production validation)

2. **Prioritize Findings by Correlation**
   - Vulnerabilities found by both SAST and DAST are highest priority
   - Example: SQL injection confirmed by Semgrep + SQLmap

3. **Tool Selection Strategy**
   - Use Semgrep for early-stage code review
   - Use ZAP for comprehensive pre-release testing
   - Use Nuclei for quick CVE checks in CI/CD
   - Use SQLmap for targeted SQL injection validation

4. **Remediation Priority**
   - Fix SQL injection vulnerabilities immediately (CVSS 9.0+)
   - Remove hardcoded secrets and rotate credentials
   - Implement security headers (CSP, HSTS, X-Frame-Options)
   - Add input validation and parameterized queries

5. **Continuous Monitoring**
   - SAST catches issues during development
   - DAST validates security in production-like environments
   - Combined approach provides defense-in-depth

---

## Conclusion

This lab demonstrated the complementary nature of SAST and DAST approaches. Semgrep identified 25 code-level vulnerabilities including SQL injection patterns, while DAST tools (ZAP, Nikto, SQLmap) confirmed exploitability and discovered 82 runtime configuration issues. The authenticated ZAP scan revealed 67% more attack surface than unauthenticated testing, highlighting the importance of testing with valid credentials. A comprehensive DevSecOps strategy requires both approaches: SAST for early detection during development, and DAST for validation in deployed environments.
