# SAST Analysis Report -- OWASP Juice Shop (Semgrep)

## SAST Tool Effectiveness

### Types of Vulnerabilities Detected

The **Semgrep** Static Application Security Testing (SAST) tool detected
multiple categories of security vulnerabilities within the analyzed
Juice Shop codebase.

1.  **SQL Injection**
    -   Detected where user-controlled input is concatenated directly
        into SQL queries executed through Sequelize.
    -   Attackers could manipulate database queries and access or modify
        sensitive data.
2.  **Cross-Site Scripting (XSS)**
    -   Occurs when user-controlled data is injected into HTML or
        `<script>` contexts without proper sanitization.
3.  **Path Traversal / Arbitrary File Access**
    -   Express routes pass user-controlled input to `res.sendFile()`
        without validation.
4.  **Open Redirect**
    -   User-controlled URLs are passed directly to `res.redirect()`.
5.  **Hardcoded Secrets**
    -   Cryptographic secrets or credentials embedded directly in the
        source code.
6.  **Unsafe Code Execution**
    -   Usage of `eval()` with potentially user-controlled input.
7.  **HTML Attribute Injection**
    -   Template variables used without quotes inside HTML attributes.
8.  **Directory Listing Exposure**
    -   Express configuration allows directory indexing, exposing
        internal files.

------------------------------------------------------------------------

### Coverage Evaluation

The Semgrep scan analyzed the **OWASP Juice Shop source code** located
under `/src` inside the container.

**Rulesets used:**

-   `p/security-audit`
-   `p/owasp-top-ten`

**Results Summary**

-   Total findings: **25**
-   Severity classification: **Blocking**
-   Multiple backend and frontend files affected.

The scan covered:

-   Backend Express routes (`/src/routes`)
-   Database query logic
-   Angular frontend templates
-   Server configuration files
-   Security utilities

This indicates strong coverage across both **server-side and client-side
code**.

------------------------------------------------------------------------

# Critical Vulnerability Analysis

## 1. SQL Injection

**Vulnerability Type:** SQL Injection\
**Severity:** Blocking\
**File:** `/src/routes/login.ts`\
**Line:** 34

Example vulnerable code:

    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })

Impact:

-   Authentication bypass
-   Unauthorized database access
-   Data manipulation

------------------------------------------------------------------------

## 2. Path Traversal / Arbitrary File Access

**Vulnerability Type:** Path Traversal\
**Severity:** Blocking\
**File:** `/src/routes/fileServer.ts`\
**Line:** 33

Example vulnerable code:

    res.sendFile(path.resolve('ftp/', file))

Impact:

-   Access to sensitive files
-   Disclosure of configuration data
-   Potential credential leakage

------------------------------------------------------------------------

## 3. Hardcoded JWT Secret

**Vulnerability Type:** Hardcoded Secret\
**Severity:** Blocking\
**File:** `/src/lib/insecurity.ts`\
**Line:** 56

Example vulnerable code:

    export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })

Impact:

-   Attackers could forge authentication tokens
-   Unauthorized access to protected resources

------------------------------------------------------------------------

## 4. Unsafe Code Execution (eval)

**Vulnerability Type:** Unsafe Code Execution\
**Severity:** Blocking\
**File:** `/src/routes/userProfile.ts`\
**Line:** 62

Example vulnerable code:

    username = eval(code)

Impact:

-   Remote Code Execution
-   Full application compromise

------------------------------------------------------------------------

## 5. Open Redirect

**Vulnerability Type:** Open Redirect\
**Severity:** Blocking\
**File:** `/src/routes/redirect.ts`\
**Line:** 19

Example vulnerable code:

    res.redirect(toUrl)

Impact:

-   Phishing attacks
-   Redirection to malicious domains

------------------------------------------------------------------------

# Authenticated vs Unauthenticated Scanning

### URL Discovery Comparison

  Scan Type         Total Alerts   High   Medium   Low   Info   Unique URLs
  ----------------- -------------- ------ -------- ----- ------ -------------
  Unauthenticated   12             0      2        6     4      16
  Authenticated     13             1      4        4     4      21

Authenticated scanning discovered **5 additional URLs with findings**
compared to the unauthenticated scan.

### Examples of Authenticated Endpoints Discovered

Examples of endpoints that typically become visible after authentication
include:

-   `/rest/basket`
-   `/rest/user/whoami`
-   `/rest/user/change-password`
-   `/rest/orders`
-   `/rest/user/profile`

### Why Authenticated Scanning Matters

Authenticated scanning is critical because many vulnerabilities exist
**behind login barriers**. Without authentication, scanners can only
test public pages. Once authenticated, tools can test:

-   User account management
-   Administrative functionality
-   Order and payment APIs
-   Personal data handling

This significantly improves **security testing coverage**.

------------------------------------------------------------------------

# DAST Multi-Tool Results

## Tool Comparison Matrix

  --------------------------------------------------------------------------
  Tool     Findings      Severity Breakdown           Best Use Case
  -------- ------------- ---------------------------- ----------------------
  ZAP      13 alert      1 High, 4 Medium, 4 Low, 4   Comprehensive web
           types         Info                         vulnerability scanning

  Nuclei   Not available Scan not executed            Fast template-based
                                                      CVE detection

  Nikto    82 findings   Mostly informational /       Web server
                         misconfiguration             misconfiguration
                                                      detection

  SQLmap   1 injection   SQL Injection detected       Deep SQL injection
           point                                      analysis
  --------------------------------------------------------------------------

------------------------------------------------------------------------

# Tool-Specific Strengths

## OWASP ZAP

**Strengths**

-   Full web application vulnerability scanning
-   Authentication support
-   Detection of many OWASP Top 10 vulnerabilities

**Example Findings**

-   SQL Injection (High)
-   Content Security Policy Header Not Set
-   Missing Anti-clickjacking Header

------------------------------------------------------------------------

## Nuclei

**Status:** Scan not executed.

Nuclei normally provides:

-   Extremely fast vulnerability scanning
-   Detection of known CVEs
-   Template-based scanning

No results were available because nuclei container didn't run.

------------------------------------------------------------------------

## Nikto

**Strengths**

-   Web server configuration testing
-   Header security analysis
-   Detection of exposed directories

**Example Findings**

-   Missing `X-XSS-Protection` header
-   `Access-Control-Allow-Origin: *`
-   Public `/ftp/` directory in robots.txt

Total findings: **82**.

------------------------------------------------------------------------

## SQLmap

**Strengths**

-   Automated SQL injection detection
-   Database fingerprinting
-   Advanced injection exploitation

**Example Finding**

Injection point discovered:

    /rest/products/search?q=

SQLmap detected:

    AND boolean-based blind SQL injection

Payload example:

    http://localhost:3000/rest/products/search?q=') AND 4822=4822 AND ('Dofr' LIKE 'Dofr

Additional details:

-   Injection points: **1**
-   HTTP requests used: **41**
-   Backend DBMS: **SQLite**

------------------------------------------------------------------------

# Overall Security Testing Summary

Combining multiple tools improves vulnerability coverage.

Observations:

-   **Semgrep (SAST)** detected insecure coding practices.
-   **ZAP** identified runtime vulnerabilities and missing security
    headers.
-   **Nikto** revealed server configuration weaknesses.
-   **SQLmap** confirmed an exploitable SQL injection vulnerability.
-   **Nuclei** results were unavailable because the scan did not
    execute.

Using both **SAST and DAST tools together** provides a more
comprehensive security assessment.

------------------------------------------------------------------------

# SAST vs DAST Correlation Analysis

## Total Findings Comparison

Security testing was performed using both **Static Application Security Testing (SAST)** and **Dynamic Application Security Testing (DAST)** tools.

| Tool | Findings |
|-----|--------|
| SAST (Semgrep) | 25 code-level findings |
| DAST (ZAP authenticated) | 8 alerts |
| DAST (Nikto) | 82 server issues |
| DAST (SQLmap) | 1 SQL injection vulnerability |

**Combined DAST findings:** 91  
**SAST findings:** 25

While DAST tools produced a larger number of findings overall, many of them relate to **runtime configuration issues**, while SAST focuses on **code-level vulnerabilities inside the application source code**.

------------------------------------------------------------------------

## Vulnerabilities Found Only by SAST

Some vulnerabilities were detected **only by static code analysis** because they exist directly in the source code and may not always be observable during runtime testing.

Examples include:

1. **Hardcoded Secrets**
   - Example: hardcoded JWT signing key in `/src/lib/insecurity.ts`.
   - Static analysis can detect embedded credentials directly in the code.

2. **Unsafe Code Execution (eval usage)**
   - Example: `eval(code)` in `/src/routes/userProfile.ts`.
   - This pattern represents a potential remote code execution risk.

3. **HTML Template Injection Risks**
   - Unquoted template attributes in Angular templates.
   - These patterns indicate potential injection vulnerabilities even if they are not triggered during dynamic testing.

SAST is particularly effective for identifying **insecure coding practices and dangerous code patterns early in the development process**.

------------------------------------------------------------------------

## Vulnerabilities Found Only by DAST

Dynamic scanning tools identified several vulnerabilities that cannot be easily detected through static analysis because they depend on **runtime behavior and server configuration**.

Examples include:

1. **Missing Security Headers**
   - Missing `Content-Security-Policy`
   - Missing `X-Content-Type-Options`
   - Missing `X-XSS-Protection`

2. **Server Misconfigurations**
   - `Access-Control-Allow-Origin: *` header allowing unrestricted cross-origin access.
   - Exposed `/ftp/` directory referenced in `robots.txt`.

3. **Runtime SQL Injection Detection**
   - SQLmap successfully confirmed a **boolean-based blind SQL injection** in:
     ```
     /rest/products/search?q=
     ```
   - This demonstrates that the vulnerability is **exploitable in a running environment**.

DAST tools are highly effective at detecting **deployment issues, misconfigurations, and vulnerabilities that occur during application execution**.

------------------------------------------------------------------------

## Why SAST and DAST Detect Different Issues

SAST and DAST operate at **different stages of the application lifecycle**, which explains why they detect different types of vulnerabilities.

### Static Analysis (SAST)

SAST analyzes the **source code without executing the application**.

Advantages:

- Detects vulnerabilities early in development
- Identifies insecure coding patterns
- Finds hidden issues not reachable through web interfaces
- Helps developers fix problems before deployment

Typical findings include:

- Hardcoded secrets
- Unsafe functions such as `eval`
- SQL query construction vulnerabilities
- Insecure cryptographic implementations

------------------------------------------------------------------------

### Dynamic Analysis (DAST)

DAST analyzes a **running application by sending HTTP requests and analyzing responses**.

Advantages:

- Tests the application in its real runtime environment
- Identifies configuration issues
- Validates whether vulnerabilities are actually exploitable
- Detects authentication and session management problems

Typical findings include:

- Missing HTTP security headers
- Server misconfiguration
- Authentication weaknesses
- Runtime SQL injection vulnerabilities

------------------------------------------------------------------------

## Security Testing Recommendation

The results clearly demonstrate that **neither SAST nor DAST alone provides complete security coverage**.

A comprehensive security testing strategy should include both approaches:

- **SAST** for detecting vulnerabilities in source code during development
- **DAST** for identifying runtime vulnerabilities and configuration issues after deployment

Using both methods together provides **defense in depth and significantly improves overall application security**.