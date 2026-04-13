# Lab 5 Submission — Security Assessment: SAST & DAST of OWASP Juice Shop

## Task 1 — Static Application Security Testing with Semgrep

### SAST Tool Assessment

Using the combined *security-audit* and *OWASP Top Ten* rulesets, Semgrep identified **25 security findings**.
Its key strengths are semantic code analysis for spotting complex injection patterns, accurate file and line references, and practical remediation suggestions.
Among the detected issues were **SQL injection, cross-site scripting (XSS), path traversal,** and **weak cryptographic practices**.

### Major Vulnerabilities Identified

1. **SQL Injection (Critical)** — `/src/routes/login.ts:34`: A Sequelize query is built through string concatenation, making authentication bypass possible.
2. **Path Traversal (High)** — `/src/routes/fileServer.ts:33`: User-controlled input is passed into `res.sendFile()` without proper validation, allowing directory traversal.
3. **Hardcoded JWT Secret (High)** — `/src/lib/insecurity.ts:56`: JWT tokens are signed with a hardcoded secret instead of using secure secret management.
4. **XSS in Templates (Medium)** — `/src/frontend/src/app/navbar/navbar.component.html:17`: Unquoted template expressions create an opportunity for script injection.
5. **Open Redirect (Medium)** — `/src/routes/redirect.ts:19`: The redirect functionality uses user input directly, with no validation in place.

---

## Task 2 — Dynamic Application Security Testing with Multiple Tools

### Comparison of DAST Tools

* **ZAP**: Reported **16 alerts** such as backup disclosures and configuration exposures. Best suited for thorough and in-depth web application scanning, although it is slower.
* **Nuclei**: Found **23 issues**, mainly exposures and misconfigurations. It is the fastest option thanks to its template-based approach.
* **Nikto**: Detected **14 findings**, mostly related to server information leaks and insecure headers.
* **SQLmap**: Successfully confirmed SQL injection vulnerabilities and proved most effective for database-focused testing.

### Advantages of Each Tool

**ZAP:** Broad coverage, both active and passive scanning, and detailed risk analysis.
**Nuclei:** Fast CVE detection, extensive community-maintained templates, and smooth CI/CD integration.
**Nikto:** Effective for identifying outdated software, insecure configurations, and exposed sensitive files.
**SQLmap:** Specialized in automated SQL injection testing, payload generation, and database fingerprinting.

### DAST Results

* **ZAP:** Discovered exposure of a backup file at `/ftp/quarantine - Copy`, which could reveal sensitive information.
* **Nuclei:** Identified missing security headers such as COOP and CSP, increasing the risk of XSS and clickjacking.
* **Nikto:** Found ETag inode leakage and exposure of `robots.txt`, both of which may help attackers during reconnaissance.
* **SQLmap:** Confirmed SQL injection at `/rest/products/search?q=apple` through boolean-based and time-based techniques.

---

## Task 3 — Relationship Between SAST and DAST

### Insights from SAST and DAST

**What SAST uniquely reveals:** Source-code weaknesses such as injection points, hardcoded secrets, template-related XSS, and path traversal flaws.
**What DAST uniquely reveals:** Runtime and deployment issues including misconfigurations, sensitive data exposure, backup leaks, and proof of exploitability.

**Main distinction:**
SAST helps uncover **coding flaws during development**, while DAST verifies **how the application behaves in a live environment and whether deployment settings are secure**.

---

## Combined Security Recommendations

**Recommended DevSecOps Process:**

1. **Development stage:** Add Semgrep to pre-commit hooks and pull request checks to catch injection and cryptographic weaknesses early.
2. **Staging stage:** Use ZAP and Nuclei to perform comprehensive dynamic security testing of the web application.
3. **Deployment stage:** Run Nikto for server-side validation and SQLmap against database-related endpoints.
4. **Ongoing automation:** Enforce SAST quality gates, schedule regular DAST scans, and continuously monitor exposures with Nuclei.

This multi-layered strategy supports **defense in depth** and helps preserve continuous security throughout the entire software development lifecycle.