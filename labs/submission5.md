# Lab 5 Submission — SAST & DAST Security Analysis of OWASP Juice Shop

**Student:** ellilin
**Date:** 2026-03-09
**Target:** bkimminich/juice-shop:v19.0.0

---

## Task 1 — Static Application Security Testing with Semgrep (3 pts)

### SAST Tool Effectiveness

Semgrep was used to perform static code analysis on the OWASP Juice Shop source code (v19.0.0). The scan analyzed 1,014 files across multiple languages (TypeScript, JavaScript, JSON, YAML, HTML, etc.) using 674 security rules.

**Results Summary:**
- Total files scanned: 1,014
- Total security findings: 25 (25 blocking)
- Rules executed: 140
- Parsed lines: ~99.9%

Semgrep effectively identified code-level vulnerabilities including SQL injection patterns, path traversal risks, and other security issues that would be exploitable at runtime.

### Critical Vulnerability Analysis

The following are the **5 most critical findings** from Semgrep results:

#### 1. SQL Injection (6 occurrences)
- **Vulnerability Type:** SQL Injection via Sequelize
- **Severity:** ERROR (Critical)
- **File:** `/src/data/static/codefixes/dbSchemaChallenge_1.ts`
- **Line:** 5
- **Description:** Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. (CWE-89)
- **Remediation:** Use parameterized queries or prepared statements.

#### 2. Path Traversal via res.sendFile (4 occurrences)
- **Vulnerability Type:** Path Traversal / Arbitrary File Read
- **Severity:** WARNING (High)
- **File:** `/src/routes/fileServer.ts`
- **Description:** The application processes user-input passed to `res.sendFile`, which can allow an attacker to arbitrarily read files on the system through path traversal.
- **Remediation:** Perform input validation and canonicalize the path before serving files.

#### 3. Directory Listing Exposure (4 occurrences)
- **Vulnerability Type:** Information Disclosure - Directory Listing
- **Severity:** WARNING (Medium)
- **File:** `/src/server.ts`
- **Description:** Server may expose directory listings, allowing attackers to discover file structure.
- **Remediation:** Configure server to disable directory listing.

#### 4. Insecure Random Number Generation (1 occurrence)
- **Vulnerability Type:** Weak Cryptography
- **Severity:** ERROR (High)
- **File:** `/src/routes/challengeServer.ts`
- **Line:** 5
- **Description:** Insecure random number generation that may be predictable.
- **Remediation:** Use cryptographically secure random number generators (crypto.randomBytes()).

#### 5. Express CORS Misconfiguration (1 occurrence)
- **Vulnerability Type:** Security Misconfiguration
- **Severity:** WARNING
- **File:** `/src/routes/orderServer.ts`
- **Description:** Cross-Origin Resource Sharing (CORS) is configured insecurely, potentially allowing unauthorized cross-origin requests.
- **Remediation:** Restrict CORS to specific origins as needed.

---

## Task 2 — Dynamic Application Security Testing with Multiple Tools (5 pts)

### Authenticated vs Unauthenticated Scanning

**ZAP Unauthenticated Scan:**
- Total URLs discovered: 95
- Scan duration: ~2 minutes
- High severity findings: 0
- Medium severity findings: 9 warnings

**ZAP Authenticated Scan:**
- Traditional spider URLs discovered: 112
- AJAX spider URLs discovered: 898
- Total unique URLs: ~1,010
- Scan duration: ~8 minutes (spider 10s + ajax spider 33s + passive scan 7s + active scan ~7 min)

**URL Discovery Comparison:**
| Scan Type | URLs Found | Ratio |
|-----------|-------------|--------|
| Unauthenticated | 95 | 1x baseline |
| Authenticated | 1,010 | ~10.6x more |

**Admin/Authenticated Endpoints Discovered:**
- `/rest/admin/application-configuration` - Admin configuration endpoint
- `/rest/admin/recurring-charge` - Recurring charge management
- `/rest/user/login` - User authentication (known from unauth scan)
- `/rest/user/change-password` - Password change functionality
- `/rest/basket/` - Shopping basket endpoints

**Why Authenticated Scanning Matters:**
Authenticated scanning reveals **60%+ more attack surface** by discovering:
1. **User-specific features** - endpoints that require valid sessions (basket, orders, payment, profile)
2. **Admin panel vulnerabilities** - administrative functions not accessible without credentials
3. **Additional API routes** - backend endpoints only exposed to authenticated users
4. **Business logic flaws** - vulnerabilities in workflows that span multiple authenticated pages

### Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|-------|-----------|---------------------|-----------------|
| **ZAP (Authenticated)** | 9 warnings | 9 Medium | Comprehensive web app testing with AJAX spider and authentication support |
| **Nuclei** | 25 matches | 1 DNS, various info | Fast template-based scanning for known vulnerabilities |
| **Nikto** | 12 items reported | 2 Low, 10 Info | Web server misconfiguration detection |
| **SQLmap** | 1 SQLi confirmed + database dump | 1 Critical (SQLi) | Specialized SQL injection testing and data extraction |

### Tool-Specific Strengths

#### ZAP (Zed Attack Proxy)
**Strengths:**
- Comprehensive scanning with multiple discovery methods (spider, AJAX spider)
- Integrated passive and active scanning
- Authentication support for testing protected areas
- AJAX spider discovers ~10x more URLs than traditional spider for modern apps
- Detailed HTML reports with evidence

**Example Findings:**
1. **Cross-Domain JavaScript Source File Inclusion** (5 instances)
   - Severity: Warning
   - Description: JavaScript files loaded from external domains without Subresource Integrity (SRI) checks

2. **Content Security Policy (CSP) Header Not Set** (5 instances)
   - Severity: Warning
   - Description: Missing CSP header allows XSS attacks and data exfiltration

3. **Deprecated Feature Policy Header Set** (5 instances)
   - Severity: Warning
   - Description: Using deprecated security headers

#### Nuclei (Fast Template-Based Scanner)
**Strengths:**
- Extremely fast scanning using pre-built templates
- Community-maintained template library (9,810+ templates)
- Excellent for detecting known CVEs and common misconfigurations
- JSON output for easy integration with other tools

**Example Findings:**
1. **DNS Rebinding Attack Detection**
   - Type: Informational
   - Description: Detected localhost pointing to private IP (127.0.0.1), potential for DNS rebinding attacks

2. **Multiple Technology Detection**
   - Detected JavaScript frameworks and libraries used
   - Identified server information disclosure

#### Nikto (Web Server Scanner)
**Strengths:**
- Specialized in HTTP header and server configuration analysis
- Fast scanning of server information disclosure
- Detects common server misconfigurations
- Good complement to other DAST tools

**Example Findings:**
1. **ETag Information Disclosure** (Medium)
   - Description: Server leaks inodes via ETags header, revealing filesystem information

2. **Interesting Directories** (Multiple)
   - `/ftp/` - FTP directory accessible (200 response)
   - `/public/` - Public directory exposed
   - `/css/` - Might contain sensitive files

3. **CORS Misconfiguration** (Info)
   - Description: `access-control-allow-origin: *` allows all origins

4. **X-Frame-Options Header Present** (Good)
   - Description: `X-Frame-Options: SAMEORIGIN` properly configured

#### SQLmap (SQL Injection Specialist)
**Strengths:**
- Deep SQL injection testing with multiple techniques
- Database fingerprinting and data extraction
- Supports time-based and boolean-based blind injection
- Can dump entire database contents
- Identifies injection points that other tools miss

**Example Findings:**
1. **SQL Injection in Search Endpoint (CONFIRMED)**
   - Endpoint: `GET /rest/products/search?q=`
   - Type: Boolean-based blind SQL injection
   - Payload: `') AND 1505=1505 AND ('sULJ' LIKE 'sULJ`
   - Impact: Allows bypassing search logic and extracting database data

2. **Database Schema Discovered**
   - Database: SQLite_masterdb
   - 21 tables identified including:
     * `Users` - Contains user accounts and credentials (bcrypt hashes)
     * `Cards` - Contains payment card information
     * `Baskets` - Shopping baskets
     * `Products` - Product catalog
     * `Challenges` - Challenge data
     * `Wallets` - Cryptocurrency wallets (with NULL values)
     * `Addresses`, `Complaints`, `Feedbacks` - Additional user data

3. **Data Extraction**
   - Successfully extracted Cards table with 6 entries:
     - User IDs, card numbers, expiry dates
     - Names: "Bjoern Kimminich", "Tim Tester", "Administrator", "Jim", "Bender"
   - Identified potential password hashes in cardNum column

---

## Task 3 — SAST/DAST Correlation and Security Assessment (2 pts)

### SAST vs DAST Comparison

| Approach | Total Findings | Key Strengths | Key Limitations |
|----------|----------------|----------------|-------------------|
| **SAST (Semgrep)** | 25 code-level findings | Fast feedback in development, detects code patterns early | Cannot detect runtime issues, server misconfigs, requires source code |
| **DAST Combined** | ~47 findings | Finds runtime vulnerabilities, tests actual behavior, no source code needed | Slower, may miss code-level issues, requires running application |
| **Total Coverage** | ~72 findings | Combined approach provides comprehensive security assessment | Each tool has blind spots |

### SAST-Only Vulnerability Types

**Found ONLY by SAST:**
1. **Hardcoded Secrets** - SAST can identify hardcoded credentials in source files
2. **Code-Level Injection Patterns** - SAST finds SQLi patterns even if not exploitable at runtime
3. **Insecure Cryptography** - SAST identifies weak random number generation and crypto usage
4. **Path Traversal in Code** - SAST finds dangerous file handling patterns

### DAST-Only Vulnerability Types

**Found ONLY by DAST:**
1. **Missing Security Headers** - DAST detects missing CSP, HSTS, X-Frame-Options headers
2. **Runtime Configuration Issues** - DAST finds CORS misconfiguration, directory listing
3. **Authentication Flaws** - DAST can test login bypass and session management
4. **Information Disclosure via HTTP** - DAST finds server version leaks, ETag issues
5. **Database Injection Confirmation** - SQLmap confirmed exploitable SQL injection in search endpoint

### Why Each Approach Finds Different Things

**SAST (Static Analysis):**
- **Pros:**
  - Shift-left testing in development phase
  - Fast feedback to developers (seconds vs minutes)
  - Scans entire codebase for patterns
  - No need for running application
  - Integrates with CI/CD pipelines
  - Low resource usage

- **Cons:**
  - Cannot detect runtime behavior
  - May produce false positives (code pattern != vulnerability)
  - Misses configuration issues
  - Requires access to source code
  - Limited to defined rulesets

**DAST (Dynamic Analysis):**
- **Pros:**
  - Tests actual running application
  - Finds runtime vulnerabilities and misconfigurations
  - Discovers real-world attack surface
  - Can test authentication and authorization
  - Works with black-box applications
  - Provides exploit confirmation

- **Cons:**
  - Slower and more resource intensive
  - May not test all code paths
  - Can impact production if not careful
  - Limited by scanning tools' capabilities
  - May miss business logic vulnerabilities

### Key Security Insights

1. **SQL Injection Confirmed:** Both SAST and DAST identified SQL injection patterns, with SQLmap confirming exploitation is possible against the search endpoint.

2. **Missing Security Headers:** Juice Shop lacks critical security headers:
   - Content-Security-Policy (CSP) - Helps prevent XSS
   - Strict-Transport-Security (HSTS) - Enforces HTTPS
   - Proper X-Frame-Options (currently has but could be more strict)

3. **Path Traversal Risk:** SAST identified `res.sendFile` usage with user input, a classic path traversal vulnerability. This could allow reading arbitrary files on the server.

4. **Information Disclosure:** Multiple findings show the application leaks information:
   - Server version via headers
   - Filesystem structure via directory listings
   - Database schema through SQLi confirmation

5. **Authentication Surface:** Authenticated scanning revealed 10x more URLs, highlighting the importance of testing behind authentication for comprehensive security assessment.

### Recommendations

**Immediate Actions:**
1. Patch SQL injection in search endpoint using parameterized queries
2. Add Content-Security-Policy header to prevent XSS
3. Implement input validation for `res.sendFile` to prevent path traversal
4. Restrict CORS origins instead of using wildcard (`*`)
5. Disable directory listing on the server

**DevSecOps Integration:**
1. **SAST in CI/CD:** Integrate Semgrep as a pre-commit or PR check to catch code-level issues early
2. **DAST in Staging:** Run authenticated ZAP scans in staging environment before production deployment
3. **Automated SQLi Testing:** Use specialized SQL injection testing in CI/CD for database-related endpoints
4. **Header Compliance:** Add security headers check to deployment pipeline
5. **Continuous Monitoring:** Implement SAST/DAST correlation to track vulnerability lifecycle

---

## Summary

This lab demonstrated the importance of using **multiple security testing approaches**:

1. **SAST** caught code-level vulnerabilities early in the development cycle
2. **DAST** confirmed runtime issues and provided exploit verification
3. **Multi-tool approach** revealed different vulnerability types than any single tool could find
4. **Authenticated scanning** revealed significantly more attack surface than unauthenticated
5. **SQLmap** provided deep database analysis confirming critical SQL injection vulnerability

The combination of SAST and DAST provides **comprehensive security coverage** for modern web applications like OWASP Juice Shop. Each tool has unique strengths, and using them together provides the best chance of discovering vulnerabilities before attackers do.
