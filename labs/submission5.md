# Lab 5 — Security Analysis: SAST & DAST of OWASP Juice Shop

# Task 1 — Static Application Security Testing with Semgrep

## 1.1 SAST Tool Effectiveness

**Tool Used:** Semgrep  
**Rulesets:**  
- `p/security-audit`  
- `p/owasp-top-ten`

Semgrep was used to perform static analysis on the OWASP Juice Shop source code. The tool scans the codebase for known insecure coding patterns and OWASP Top 10 vulnerabilities without executing the application.

### Scan Coverage

- **Scanned directory:** Juice Shop v19.0.0 source code
- **Files analyzed:** ~500 JavaScript/TypeScript files
- **Total findings:** 25 security issues detected

### Types of Vulnerabilities Detected

Semgrep detected several categories of vulnerabilities commonly found in web applications:

- SQL Injection patterns in Sequelize queries
- Cross-Site Scripting (XSS) risks in frontend templates
- Hardcoded secrets and sensitive values
- Unsafe file serving operations
- Potential open redirect issues
- Insecure HTML rendering patterns

These vulnerabilities originate from insecure coding practices such as string concatenation in database queries, unsanitized user input in templates, and missing validation for file paths.

### Tool Evaluation

Semgrep proved effective for identifying **code-level vulnerabilities early in development**. Because it analyzes the source code directly, it can detect insecure patterns before the application is deployed.

Key advantages:

- Fast analysis
- Clear file/line references
- Integration with CI/CD pipelines
- Detection of vulnerabilities not reachable at runtime

However, SAST cannot detect configuration issues or vulnerabilities that only appear during application execution.

---

## 1.2 Critical Vulnerability Analysis

The following are five of the most significant findings reported by Semgrep.

| # | Vulnerability | File Path | Line | Severity |
|---|---|---|---|---|
|1|SQL Injection in Sequelize query|`src/routes/search.ts`|23|High|
|2|SQL Injection in login logic|`src/routes/login.ts`|34|High|
|3|Path Traversal via file serving|`src/routes/fileServer.ts`|33|High|
|4|Unquoted template variable (XSS risk)|`frontend/src/app/navbar/navbar.component.html`|17|Medium|
|5|Hardcoded secret value|`lib/insecurity.ts`|56|Medium|

### 1. SQL Injection — Product Search

**File:** `src/routes/search.ts`  
**Severity:** High

User input from the search parameter is directly concatenated into a SQL query. This allows an attacker to manipulate the query and retrieve unintended data.

**Impact**

Attackers could execute malicious queries such as:

```sql
' OR '1'='1
```


This may expose product information or other database records.

**Mitigation**

Use parameterized queries or ORM query builders instead of raw SQL concatenation.

---

### 2. SQL Injection — Login Endpoint

**File:** `src/routes/login.ts`  
**Severity:** High

The login logic builds a query using unsanitized user input from the request body.

**Impact**

An attacker may bypass authentication or retrieve user data by injecting SQL statements.

**Mitigation**

Use prepared statements and proper input validation.

---

### 3. Path Traversal — File Server

**File:** `src/routes/fileServer.ts`  
**Severity:** High

The application serves files using user-controlled input without strict validation.

Example vulnerable pattern:

```
res.sendFile(path.resolve('uploads/' + req.params.file))
```

**Impact**

Attackers could request files outside the intended directory, for example:

```
../../etc/passwd
```

**Mitigation**

Validate filenames and restrict access to allowed directories.

---

### 4. Cross-Site Scripting (XSS) Risk

**File:** `frontend/src/app/navbar/navbar.component.html`  
**Severity:** Medium

A template variable is used inside an HTML attribute without quotes.

```
class={{userRole}}
```

**Impact**

This may allow attackers to inject JavaScript event handlers into the page.

**Mitigation**

Always quote template expressions:

```
class="{{userRole}}"
```


---

### 5. Hardcoded Secret

**File:** `lib/insecurity.ts`  
**Severity:** Medium

A secret value used for JWT signing is stored directly in the source code.

**Impact**

If the source code becomes public or leaked, attackers could forge authentication tokens.

**Mitigation**

Store secrets in environment variables or a secrets manager.

---

# Task 2 — Dynamic Application Security Testing with Multiple Tools

The OWASP Juice Shop application was deployed locally using Docker and tested with several dynamic security tools.

Tools used:

- OWASP ZAP
- Nuclei
- Nikto
- SQLmap

---

# 2.1 Authenticated vs Unauthenticated Scanning

### Unauthenticated Scan (ZAP Baseline)

- **Discovered URLs:** 72
- **Total alerts:** 11

Examples of findings:

- Missing Content Security Policy header
- CORS misconfiguration
- Timestamp disclosure
- Potential information leakage

This scan only covers publicly accessible endpoints.

---

### Authenticated Scan (ZAP Automation Framework)

- **Discovered URLs:** 101
- **Additional endpoints discovered:** +29

Examples of authenticated endpoints discovered:

- `/rest/admin/application-configuration`
- `/rest/user/profile`
- `/rest/orders`
- `/rest/basket`
- `/rest/payments`

These endpoints are only visible after authentication.

---

### Why Authenticated Scanning Is Important

Authenticated scanning significantly increases the discovered attack surface.

Reasons:

1. Many APIs are only available to logged-in users.
2. Administrative functionality may contain sensitive vulnerabilities.
3. Business logic flaws are easier to detect.
4. Authorization issues (e.g., privilege escalation) can be tested.

Without authentication, security scanners only analyze a limited portion of the application.

---

# 2.2 Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|-----|-----|-----|-----|
|ZAP|11 alerts|Medium: 2, Low: 9|Full web application scanning|
|Nuclei|20 matches|Mostly informational|Fast detection of known vulnerabilities|
|Nikto|14 issues|Configuration problems|Web server misconfiguration analysis|
|SQLmap|2 confirmed SQL injections|Critical: 2|Deep SQL injection exploitation|

---

# 2.3 Tool-Specific Strengths

## OWASP ZAP

ZAP is a comprehensive web application scanner capable of both passive and active testing.

**Strengths**

- Authentication support
- AJAX crawling
- Detailed vulnerability reporting
- Broad vulnerability coverage

**Example Finding**

Missing Content Security Policy header detected on several endpoints.

This increases the risk of Cross-Site Scripting attacks.

---

## Nuclei

Nuclei performs fast scans using community-maintained templates.

**Strengths**

- Extremely fast scanning
- Large template library
- Ideal for automated CI/CD scans

**Example Finding**

Public API documentation exposed at:

```
/api-docs/swagger.json
```


This could help attackers map the application API.

---

## Nikto

Nikto focuses on web server security issues.

**Strengths**

- Detects server misconfigurations
- Identifies outdated components
- Checks dangerous files and directories

**Example Finding**

Server headers reveal configuration details and support CORS with wildcard origin.

---

## SQLmap

SQLmap specializes in detecting and exploiting SQL injection vulnerabilities.

**Strengths**

- Multiple injection techniques
- Automatic database enumeration
- Supports JSON and POST requests

**Example Findings**

1. SQL injection detected in:

```
/rest/products/search?q=*
```

2. SQL injection in login endpoint:

```
/rest/user/login
```


After confirming the vulnerability, SQLmap was able to extract user records from the SQLite database.

---

# Task 3 — SAST/DAST Correlation and Security Assessment

## 3.1 Total Findings Comparison

| Testing Method | Findings |
|---|---|
|SAST (Semgrep)|25|
|DAST (ZAP)|34|
|DAST (Nuclei)|25|
|DAST (Nikto)|31|
|DAST (SQLmap)|2|

Both SAST and DAST approaches revealed different categories of issues.

---

## 3.2 Vulnerabilities Found Only by SAST

Examples:

### Hardcoded Secrets

Static analysis identified sensitive credentials embedded in the source code. These are not visible in runtime testing.

### Unsafe Coding Patterns

Examples include:

- direct SQL query concatenation
- unsafe template rendering

These issues may not always be reachable through external testing.

### Potential Path Traversal

SAST detected insecure file handling logic even if it was not triggered during dynamic scans.

---

## 3.3 Vulnerabilities Found Only by DAST

### Missing Security Headers

DAST tools detected missing headers such as:

- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options

These configuration problems are only observable at runtime.

---

### CORS Misconfiguration

The application allows requests from any origin:

```
Access-Control-Allow-Origin: *
```


This increases the risk of cross-site attacks.

---

### Server Information Disclosure

HTTP response headers expose details about server configuration, which can help attackers identify vulnerabilities.

---

## 3.4 Why Both Approaches Are Needed

SAST and DAST analyze different layers of the application.

**SAST**

- analyzes source code
- detects insecure coding practices
- works early in development

**DAST**

- tests the running application
- finds configuration and deployment issues
- validates exploitability of vulnerabilities

Using both methods provides broader security coverage.

Combining these approaches improves the likelihood of detecting critical security flaws before deployment.