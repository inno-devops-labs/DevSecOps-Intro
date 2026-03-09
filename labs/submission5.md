# Lab 5: Security Analysis (SAST & DAST) of OWASP Juice Shop

## Task 1: Static Application Security Testing with Semgrep

### 1.1 SAST Tool Effectiveness
Semgrep successfully analyzed the source code of the OWASP Juice Shop and identified **25 security vulnerabilities** within the tracked codebase. It scanned a total of 1014 files (primarily TypeScript, JavaScript, and JSON). 

Semgrep was particularly effective at detecting logic and code-level misconfigurations, uncovering vulnerabilities like unquoted template variables that could lead to Cross-Site Scripting (XSS) and server configurations that inappropriately enabled directory listing. These are vulnerabilities that are much more complex and time-consuming to discover reliably through dynamic black-box testing alone.

### 1.2 Critical Vulnerability Analysis
Here are the top 5 critical findings identified by the Semgrep scan:

1. **Unquoted Template Variable (Potential XSS)**
   - **File:** `/src/views/dataErasureForm.hbs` (Line 21)
   - **Severity:** WARNING
   - **Description:** A template variable is unquoted as an HTML attribute, which can allow an attacker to inject custom JavaScript handlers.

2. **Directory Listing/Indexing Enabled (Sensitive Data Exposure)**
   - **File:** `/src/server.ts` (Line 281)
   - **Severity:** WARNING
   - **Description:** Directory listing is enabled, which may lead to the disclosure of sensitive files and structure.

3. **Directory Listing/Indexing Enabled (Sensitive Data Exposure)**
   - **File:** `/src/server.ts` (Line 277)
   - **Severity:** WARNING
   - **Description:** Directory listing is enabled, which may lead to the disclosure of sensitive files and structure.

4. **Directory Listing/Indexing Enabled (Sensitive Data Exposure)**
   - **File:** `/src/server.ts` (Line 273)
   - **Severity:** WARNING
   - **Description:** Directory listing is enabled, which may lead to the disclosure of sensitive files and structure.

5. **Directory Listing/Indexing Enabled (Sensitive Data Exposure)**
   - **File:** `/src/server.ts` (Line 269)
   - **Severity:** WARNING
   - **Description:** Directory listing is enabled, which may lead to the disclosure of sensitive files and structure.

---

## Task 2: Dynamic Application Security Testing with Multiple Tools

### 2.1 Authenticated vs Unauthenticated Scanning
- **Unauthenticated Scan:** Discovered 18 unique URLs, identifying only 12 baseline alerts strictly linked to the initial landing points easily accessible from the outside.
- **Authenticated Scan:** Leveraging ZAP's Automation Framework alongside valid admin credentials, the AJAX spider discovered ~1,200 unique URLs. 
- **Admin/Authenticated Endpoints Discovered:** `/rest/admin/application-configuration`, `/rest/admin/application-version`.
- **Value of Authenticated Scanning:** The majority of modern web application logic is locked behind user sessions. By scanning strictly without authentication, testing coverage remains fundamentally limited to public paths, completely missing complex underlying platform features (e.g. basket items, admin interfaces, user profiles) which typically house the most severe injection and logic vulnerabilities.

### 2.2 Tool Comparison Matrix

| Tool | Total Findings | Severity Breakdown | Best Use Case |
|---|---|---|---|
| **OWASP ZAP** | ~40-60+ | Medium/High | Comprehensive web vulnerability scanning and heavily driven dynamic exploration (like XSS, CSRF). |
| **Nuclei** | ~10-15 | Info/Low | Extremely fast template-based continuous scanning; exceling at rapid technology fingerprinting and CVE detection. |
| **Nikto** | 82 | Low/Medium | Scanning raw web server configurations for missing security headers, outdated software, and directory files. |
| **SQLmap** | 1 (Injection) | High/Critical | Deep targeted analysis of endpoints for SQL Injection vulnerabilities and database enumeration. |

### 2.3 Tool-Specific Strengths
- **OWASP ZAP:** Excels at thorough app logic parsing via Ajax and authenticated Spidering. Successfully bypasses login barriers to analyze stateful endpoints.
- **Nuclei:** Lightweight and driven by YAML community templates. Example finding: Generic technology/framework matches (e.g., Node.js and Express detection headers).
- **Nikto:** Superior for low-level backend server reviews. Example finding: The `X-XSS-Protection` header is not defined; Entry `/ftp/` in `robots.txt` returned a 200 HTTP code.
- **SQLmap:** Extremely efficient at automating difficult binary/time-based blind SQLi discovery. Example finding: Identified boolean-based blind injection point in SQLite on the `#1` URI parameter (`AND boolean-based blind - WHERE or HAVING clause`).

---

## Task 3: SAST/DAST Correlation and Security Assessment

### 3.1 SAST vs DAST Comparison
**Findings summary:**
- **SAST (Semgrep):** 25 code-level structural warnings
- **DAST (Combined Tools):** ~100+ runtime, interaction, and configuration issues 

### 3.2 Key Differences
**Vulnerabilities Found ONLY by SAST:**
1. **Source Code Formatting Vulnerabilities:** e.g., Unquoted Handlebars template parameters. A dynamic scanner would just see the final rendered HTML and may struggle to deterministically tie it back to bad framework syntax.
2. **Hidden Feature Toggles/Comments:** Direct reading of commented-out API keys, testing logic, or configuration files not publicly rendered to the client.

**Vulnerabilities Found ONLY by DAST:**
1. **Server Header Misconfigurations:** e.g. Missing `X-XSS-Protection` or permissive `Access-Control-Allow-Origin: *`. These are injected natively by the web server runtime, meaning SAST tools scanning Application Code won't find them if they exist in a separate deployment configuration.
2. **Blind SQL Injection Confirmation:** While SAST can guess a query string looks unsafe, DAST tools like SQLmap actively prove the exploitability by passing Boolean/Time delay queries and capturing runtime output.

### 3.3 Security Recommendation
Both SAST and DAST methodologies are strictly required for establishing comprehensive DevSecOps capabilities. **SAST** excels as a developer-centric quality gate that produces fast baseline checks pre-commit, discovering systematic code-defects before they are deployed. **DAST** works optimally in staging to confirm real-world exploitability, catch server-level structural gaps, and execute complex authentication-backed analysis. Utilizing them sequentially bridges both development and runtime security gaps comprehensively. 