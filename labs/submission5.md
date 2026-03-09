# Lab 5 — Security Analysis: SAST & DAST of OWASP Juice Shop

## Task 1 — Static Application Security Testing with Semgrep

### 1 SAST Tool Effectiveness

Semgrep summary report:
```
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 25 (25 blocking)
 • Rules run: 140
 • Targets scanned: 1014
 • Parsed lines: ~99.9%
 • Scan skipped: 
   ◦ Files larger than  files 1.0 MB: 8
   ◦ Files matching .semgrepignore patterns: 139
 • Scan was limited to files tracked by git
 • For a detailed list of skipped files and lines, run semgrep with the --verbose flag
Ran 140 rules on 1014 files: 25 findings.
```

#### Vulnerability Types Detected

From the scan output, Semgrep detected multiple vulnerability classes including:

##### 1. SQL Injection

Detected in multiple backend routes where user input is directly concatenated into SQL queries.

Example pattern detected:
```
SELECT * FROM Products WHERE name LIKE '%${criteria}%'
```
Risk:

Attackers can manipulate queries using payloads like ' OR 1=1--

Detected in:
```
search.ts
login.ts
dbSchemaChallenge_1.ts
dbSchemaChallenge_3.ts
unionSqlInjectionChallenge_*
```

#### 2. Cross-Site Scripting (XSS)

Detected in:
- HTML template attributes without quotes
- Raw HTML construction using user input
- Script tag injection

Examples:
```
alt={{applicationName}}
```
and
```
'<script ...>' + subs + '</script>'
```
Risk:

Malicious JavaScript execution in user browsers

##### 3. Path Traversal / Arbitrary File Access

Detected when user input is passed to res.sendFile() without validation

Example:
```
res.sendFile(path.resolve('ftp/', file))
```
Risk:

Attacker may access sensitive system files

Example exploit:
```
../../../../etc/passwd
```
##### 4. Hardcoded Credentials

Semgrep detected a hardcoded JWT signing key

Example:
```
jwt.sign(user, privateKey, { expiresIn: '6h' })
```
Risk:

If leaked, attackers can forge authentication tokens.

##### 5. Open Redirect

Detected in redirect logic using unvalidated user input

Example:
```
res.redirect(toUrl)
```
Risk:

Phishing attacks via malicious redirects

### Task 2 — Dynamic Application Security Testing with Multiple Tools

#### Authenticated vs Unauthenticated ZAP Scanning

URL Discovery Comparison by scan type
- Unauthenticated baseline: 95 URLS
- Authenticated (spider): 58 URLS
- Authenticated (AJAX spider)	567	
- Total authenticated: 625 (Combined)

The authenticated scan discovered **625** URLs, compared to **95** URLs during the unauthenticated baseline scan

The largest increase came from the AJAX spider, which discovered 567 URLs by executing client-side JavaScript and interacting with the Angular-based single-page application. Traditional crawlers cannot interpret JavaScript navigation logic, which is why they discovered far fewer endpoints


Several endpoints were only visible after logging in as an administrator:
```
/rest/admin/application-configuration — exposes application configuration settings and feature toggles
/rest/user/whoami — returns details of the currently authenticated user
/rest/basket/:id — endpoint containing a user's shopping basket
/profile — user profile management page
```
These endpoints represent sensitive application functionality that is completely invisible to unauthenticated scanners

#### Why Authenticated Scanning Matters

As seen before, unauthenticated scans only test functionality available to anonymous visitors, such as login pages, static resources, and public product listings. However, most business-critical functionality is located behind authentication barriers.

Authenticated scanning enables security tools to test:
- Administrative APIs
- User account management functions
- Sensitive user data endpoints

In this case, enabling authentication increased the attack surface by over 500 additional URLs, significantly improving vulnerability detection coverage

#### Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|------|----------|--------------------|---------------|
| ZAP (auth) | 15 alerts | 1 High, 5 Medium, 4 Low | Full web app scanning |
| ZAP (unauth) | 13 alerts | 0 High, 2 Medium, 6 Low | Fast scan across public endpoints |
| Nuclei | 25 matches | 1 Medium, 23 Info | Fast detection of known vulnerabilities and technology stack used in web app |
| Nikto | 84 findings | - | Server misconfig and exposed files |
| SQLmap | 1 confirmed SQL injection | Critical | SQLi detected |

#### Tool strenghts
##### ZAP
OWASP ZAP provides full web application scanning with support for authentication, session handling, and active vulnerability testing. It can crawl protected areas and automatically send attack payloads to discovered endpoints

Example findings:
- SQLi detected in the product search endpoint
- Missing CSP header which increases risk of cross-site scripting attacks

##### Nuclei
Nuclei is optimized for speed and large-scale scanning using community vulnerability templates

Example findings:
- Prometheus metrics endpoint exposed `/metrics`
- Public Swagger API documentation accessible without authentication

##### Nikto — Server Misconfiguration Detection
Nikto focuses on identifying web server configuration issues, exposed directories, and leftover backup files

Example findings:
- Publicly accessible `/ftp/` directory containing backup files
- Missing security headers such as Content-Security-Policy and Strict-Transport-Security

##### SQLmap — Advanced SQL Injection Exploitation
SQLmap specializes in detecting and exploiting SQL injection vulnerabilities and extracting database information

Example findings:
Confirmed boolean-based blind SQL injection in `/rest/products/search`
Identified the backend database as SQLite

### SAST vs DAST Comparison

#### Total Findings Comparison

| Testing Method | Tool(s) Used | Total Findings |
|----------------|--------------|----------------|
| SAST | Semgrep | 25 |
| DAST | ZAP, Nuclei, Nikto, SQLmap | 123 |

Static analysis using Semgrep detected **25 code-level vulnerabilities**, while the combined dynamic testing tools detected **123 runtime and configuration issues**.  
DAST tools produced a larger number of findings because they analyze the **running application, server configuration, and exposed endpoints**, while SAST focuses only on the source code.

---

#### Vulnerabilities Found Only by SAST

Static analysis identified several issues that are difficult to detect through runtime testing:

- **Hardcoded Secrets** – JWT signing key embedded directly in source code
- **Unsafe Code Execution (`eval`)** – Potential remote code execution through dynamic code evaluation
- **SQL Injection Patterns in Source Code** – Unsafe string concatenation in database queries before the application is executed

These vulnerabilities exist **within the application code itself**, so they are easier to detect by analyzing source files rather than interacting with the running application



#### Vulnerabilities Found Only by DAST

Dynamic testing tools discovered security problems related to the **runtime environment and server configuration**, including:

- **Missing Security Headers** (e.g, CSP, HSTS)
- **Exposed Directories and Backup Files** eg `/ftp/` directory
- **Publicly Accessible Monitoring Endpoints** like `/metrics`

These issues cannot be detected by static analysis because they depend on **how the application is deployed and configured at runtime**


#### Why SAST and DAST Find Different Vulnerabilities

SAST and DAST use fundamentally different approaches:

- SAST analyzes the application source code without running it. This allows detection of insecure coding practices such as hardcoded secrets, unsafe functions, and injection-prone query construction

- DAST tests the application while it is running by sending HTTP requests and analyzing responses. This enables discovery of misconfigurations, exposed endpoints, authentication issues, and vulnerabilities in deployed environments

Because they examine different layers of the system, each method uncovers different categories of vulnerabilities


#### Conclusion

Using both SAST and DAST provides **more comprehensive security coverage**
SAST helps developers identify vulnerabilities early during development, while DAST validates the security of the deployed application and infrastructure

Combining both approaches ensures that **code-level flaws and runtime configuration issues are detected before attackers can exploit them**