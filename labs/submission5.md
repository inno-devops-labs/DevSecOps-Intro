## Task 1 — Static Application Security Testing with Semgrep

### 1.1 Setup

For SAST analysis, I cloned the OWASP Juice Shop source code into:

- `labs/lab5/semgrep/juice-shop`

I used Semgrep in Docker with these rulesets:

- `p/security-audit`
- `p/owasp-top-ten`

Generated artifacts:

- `labs/lab5/semgrep/semgrep-results.json`
- `labs/lab5/semgrep/semgrep-report.txt`
- `labs/lab5/analysis/sast-analysis.txt`

### 1.2 SAST Tool Effectiveness

Semgrep was effective at identifying code-level security issues directly in the OWASP Juice Shop source code.  
The scan completed successfully and detected **25 findings** across **1014 scanned targets** using **140 security rules**.  
Parser coverage was very high, with approximately **99.9% of lines parsed**.

The scan results show that Semgrep is particularly effective at detecting:

- SQL injection patterns in raw Sequelize queries
- unsafe handling of user-controlled input
- insecure Express.js configuration patterns
- template-related issues that may lead to client-side injection risks

**Coverage summary:**
- Total findings: **25**
- Severity distribution: **7 ERROR**, **18 WARNING**
- Targets scanned: **1014**
- Files with findings: **20**
- Approximate repository file count: **1186**
- Rules run: **140**
- Parsed lines: **~99.9%**

This demonstrates that Semgrep provides strong static code coverage and is useful early in the DevSecOps lifecycle, especially during pull requests and pre-merge validation.

### 1.3 Five Most Critical Semgrep Findings

#### Finding 1
- Vulnerability type: **SQL Injection**
- File path and line: `data/static/codefixes/dbSchemaChallenge_1.ts:5`
- Severity: **ERROR / Blocking**
- Why critical: This code concatenates user-controlled input directly into a raw SQL query. An attacker could manipulate the query and retrieve unintended data from the database.

#### Finding 2
- Vulnerability type: **SQL Injection**
- File path and line: `data/static/codefixes/dbSchemaChallenge_3.ts:11`
- Severity: **ERROR / Blocking**
- Why critical: The query is built using a template string with unsanitized input (`${criteria}`), which creates a direct SQL injection risk and could allow unauthorized access to application data.

#### Finding 3
- Vulnerability type: **SQL Injection (UNION-style injection pattern)**
- File path and line: `data/static/codefixes/unionSqlInjectionChallenge_1.ts:6`
- Severity: **ERROR / Blocking**
- Why critical: This pattern is dangerous because attackers may be able to alter query structure and perform UNION-based SQL injection to extract additional records or metadata from the database.

#### Finding 4
- Vulnerability type: **Directory Listing Enabled**
- File path and line: `server.ts:277`
- Severity: **WARNING**
- Why critical: Enabled directory listing can expose sensitive files, internal structure, and implementation details to attackers, making further exploitation easier.

#### Finding 5
- Vulnerability type: **Unquoted Template Variable / Potential XSS Risk**
- File path and line: `views/dataErasureForm.hbs:21`
- Severity: **WARNING**
- Why critical: An unquoted template variable inside an HTML attribute can allow malicious injection into the page markup, potentially enabling client-side script injection or event-handler abuse.

---

# Task 2 — Dynamic Application Security Testing (DAST)

## 2.1 Authenticated vs Unauthenticated Scanning

Two OWASP ZAP scans were performed during the lab:

1. **Unauthenticated baseline scan**
2. **Authenticated scan using the ZAP Automation Framework**

### URL Discovery Comparison

The authenticated scan significantly expanded the attack surface compared to the baseline scan.

| Scan Type                      | URLs Discovered |
| ------------------------------ | --------------- |
| ZAP Baseline (Unauthenticated) | **95 URLs**     |
| ZAP Authenticated Spider       | **112 URLs**    |
| ZAP Authenticated AJAX Spider  | **1,026 URLs**  |

The AJAX spider discovered over **1,000 endpoints**, which is more than **10× the number of URLs** discovered by the unauthenticated scan.

This happens because the AJAX spider executes client-side JavaScript and navigates dynamic application routes that are not visible during traditional crawling.

### Examples of Authenticated Endpoints

During authenticated scanning, ZAP discovered several endpoints that are only available to authenticated users.

Examples include:

* `/rest/admin/application-configuration`
* `/rest/user/whoami`
* `/rest/basket`
* `/rest/orders`

The endpoint:

```
/rest/admin/application-configuration
```

is part of the **administrative API** and can only be accessed after successful authentication.

### Why Authenticated Scanning Matters

Authenticated scanning is essential because many vulnerabilities exist only inside **protected application functionality**.

Without authentication, security scanners can only test:

* public pages
* static resources
* limited API routes

Authenticated scanning allows testing of:

* administrative APIs
* user-specific features
* session management
* authorization behavior

In this lab, authentication dramatically expanded the discovered attack surface and enabled detection of administrative endpoints.

---

# 2.2 Tool Comparison Matrix

Multiple DAST tools were used to analyze the Juice Shop application. Each tool focuses on different vulnerability categories and testing approaches.

| Tool   | Findings                      | Severity Breakdown                                                                                   | Best Use Case                                                                                            |
| ------ | ----------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| ZAP    | **10 alerts**                 | Mostly medium/warning alerts related to security headers, JavaScript risks, and configuration issues | Comprehensive web application scanning with crawling, authentication support, and active/passive testing |
| Nuclei | **5 findings**                | 1 medium, 4 informational                                                                            | Fast template-based detection of exposed endpoints, services, and known patterns                         |
| Nikto  | **14 findings**               | Mostly informational observations related to server configuration and exposed paths                  | Web server configuration assessment and discovery of interesting directories                             |
| SQLmap | **1 confirmed vulnerability** | Boolean-based blind SQL injection                                                                    | Deep SQL injection verification and exploitation testing                                                 |

---

# 2.3 Tool-Specific Strengths

Each tool used in the DAST phase demonstrated different strengths.

---

## OWASP ZAP

OWASP ZAP is a comprehensive web application security scanner capable of performing both passive and active vulnerability detection.

Key strengths observed in this lab:

* automated crawling of application structure
* support for **authenticated scanning**
* discovery of dynamic routes via **AJAX spider**
* passive and active vulnerability detection

Example observations:

* authenticated scanning discovered the **administrative endpoint**

```
/rest/admin/application-configuration
```

* AJAX crawling expanded coverage from **95 URLs to over 1,000 endpoints**

ZAP provided the broadest visibility into the application's runtime behavior and attack surface.

---

## Nuclei

Nuclei is a fast template-based vulnerability scanner that identifies known exposures using predefined templates.

Key strengths:

* extremely fast scanning
* detection of exposed endpoints and services
* technology fingerprinting
* easy CI/CD integration

Example findings:

* **Prometheus Metrics endpoint detected**

```
/metrics
```

* **Public Swagger API detected**

```
/api-docs/swagger.yaml
```

These findings demonstrate how Nuclei quickly identifies exposed operational or development endpoints.

---

## Nikto

Nikto focuses on **web server configuration analysis and HTTP-level observations**.

Key strengths:

* detection of server misconfigurations
* identification of interesting directories
* inspection of HTTP headers
* analysis of robots.txt disclosures

Example findings:

* **Server leaks filesystem information via ETag headers**
* `/ftp/` directory referenced in `robots.txt` was accessible with HTTP 200

Nikto is particularly useful during **deployment validation** to detect server-level configuration weaknesses.

---

## SQLmap

SQLmap is a specialized tool designed specifically to detect and exploit SQL injection vulnerabilities.

Key strengths:

* automated SQL injection detection
* database-specific testing (SQLite in this lab)
* exploitation and data extraction capabilities
* verification of real vulnerability exploitability

Example finding from this lab:

SQLmap confirmed a **Boolean-based blind SQL injection vulnerability** in the search endpoint:

```
http://localhost:3000/rest/products/search?q=
```

This was the most critical vulnerability detected during the DAST phase because it represents a **confirmed exploitable database injection flaw**.

---

## Task 3 — SAST/DAST Correlation and Security Assessment

### 3.1 SAST vs DAST Comparison

The correlation analysis showed that both SAST and DAST approaches identified important but different categories of security issues.

#### Total Findings Comparison

- **SAST (Semgrep): 25 findings**
- **Combined DAST findings: 30**
  - ZAP (authenticated): 10 alerts
  - Nuclei: 5 findings
  - Nikto: 14 findings
  - SQLmap: 1 confirmed SQL injection vulnerability

This result shows that DAST produced a slightly higher total number of runtime observations and vulnerabilities, while SAST provided deeper visibility into insecure code patterns inside the source code.

---

### Vulnerability Types Found Only by SAST

The following vulnerability types were identified **only by SAST**:

- **SQL injection patterns in source code**
  - Semgrep detected raw Sequelize queries built from user-controlled input in multiple source files.
- **Template-level injection risks**
  - Example: unquoted template variables in HTML attributes, which may lead to XSS-like risks.
- **Insecure Express.js code/configuration patterns**
  - Example: code-level directory listing exposure identified directly in the application source.

These issues were visible only in SAST because Semgrep analyzes the source code directly, including files and code paths that may not always be exercised during runtime scanning.

---

### Vulnerability Types Found Only by DAST

The following vulnerability types were identified **only by DAST**:

- **Missing or weak HTTP/runtime security controls**
  - ZAP identified missing security headers and browser-side protections such as CSP-related issues.
- **Exposed runtime endpoints and operational interfaces**
  - Nuclei detected `/metrics` and `/api-docs/swagger.yaml`.
- **Server-level disclosure and exposed paths**
  - Nikto identified ETag inode leakage, `robots.txt` disclosures, and accessible directories such as `/ftp/`.
- **Confirmed exploitability of SQL injection**
  - SQLmap confirmed a Boolean-based blind SQL injection vulnerability in the product search endpoint.

These issues were visible only in DAST because they depend on how the application behaves while running, how it responds over HTTP, and what is exposed after deployment.

---

### Why SAST and DAST Find Different Things

SAST and DAST find different issues because they analyze different layers of the system.

**SAST**:
- analyzes source code directly
- identifies insecure coding patterns before deployment
- works even on code paths that are not triggered during testing
- is best for early feedback during development

**DAST**:
- interacts with the live application from the outside
- reveals runtime behavior, deployment configuration, and exposed endpoints
- validates whether a vulnerability is actually reachable or exploitable
- is best for testing the real attack surface of the deployed system

SAST was strong at identifying **code-level SQL injection risks and insecure implementation patterns**, while DAST was strong at identifying **runtime exposure, authenticated attack surface, server misconfiguration, and confirmed exploitability**.

---

### Correlation Between SAST and DAST Findings

A strong correlation was observed for SQL injection.

- **Semgrep** detected several source-code patterns where raw SQL queries were built using user-controlled input.
- **SQLmap** then confirmed a real **Boolean-based blind SQL injection** vulnerability in the product search endpoint at runtime.

This correlation is important because it demonstrates how SAST and DAST complement each other:

- **SAST shows where insecure code exists**
- **DAST proves whether the weakness is actually exploitable in the running application**

This is exactly why both approaches should be used together in a DevSecOps pipeline.

---

### Security Assessment and Recommendations

Based on the combined SAST and DAST results, the following actions are recommended:

1. **Fix SQL injection vulnerabilities first**
   - Replace raw query construction with parameterized queries or prepared statements.
   - Review all code paths flagged by Semgrep for user-controlled SQL input.

2. **Reduce unnecessary runtime exposure**
   - Restrict or disable public access to `/metrics` and `/api-docs/swagger.yaml` unless explicitly required.
   - Review access to `/ftp/` and other interesting paths disclosed via `robots.txt`.

3. **Improve HTTP security posture**
   - Add missing security headers such as a stronger Content Security Policy.
   - Review CORS configuration and other browser-facing protections.

4. **Use both SAST and DAST continuously**
   - Run **Semgrep** during pull requests and pre-merge checks.
   - Run **ZAP** in staging with authentication enabled.
   - Use **Nuclei** for fast exposure checks.
   - Use **Nikto** for server-level validation.
   - Use **SQLmap** as a targeted follow-up when SQL injection is suspected.
