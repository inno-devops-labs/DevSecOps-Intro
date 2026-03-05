# Lab 5 — SAST & DAST Security Analysis of OWASP Juice Shop

## Environment
- Target application: **OWASP Juice Shop v19.0.0**
- SAST tool: **Semgrep**
- DAST tools: **OWASP ZAP**, **Nuclei**, **Nikto**, **SQLmap**
- Platform used for execution: **Windows PowerShell + Docker Desktop**

---

## Task 1 — SAST Analysis with Semgrep

### 1.1 SAST Tool Effectiveness

Semgrep was used to statically analyze the Juice Shop source code with security-focused rulesets. It detected **25 code-level findings**, which shows good coverage for early-stage security review of the codebase. Static analysis is especially useful for identifying insecure coding patterns before deployment, including SQL injection patterns, tainted input flowing into ORM/database calls, and other source-level issues that are not dependent on runtime configuration.

In this lab, the Semgrep output was dominated by **SQL injection-related findings** in Sequelize-based code paths. This is a strong example of what SAST does well: it catches insecure patterns directly in source files and points to exact locations where user-controlled input may reach unsafe queries.

### 1.2 Top-5 Critical Findings from Semgrep

| # | Rule | Severity | File:Line | Vulnerability Type |
|---:|---|---|---|---|
| 1 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | **ERROR** | `/src/data/static/codefixes/dbSchemaChallenge_1.ts:5` | SQL Injection |
| 2 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | **ERROR** | `/src/data/static/codefixes/dbSchemaChallenge_3.ts:11` | SQL Injection |
| 3 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | **ERROR** | `/src/data/static/codefixes/unionSqlInjectionChallenge_1.ts:6` | SQL Injection |
| 4 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | **ERROR** | `/src/data/static/codefixes/unionSqlInjectionChallenge_3.ts:10` | SQL Injection |
| 5 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | **ERROR** | `/src/routes/login.ts:34` | SQL Injection |

All five top findings are high-value because they indicate user input reaching query logic without proper sanitization or parameterization. The finding in `login.ts` is especially important because authentication endpoints are high-risk and often directly exposed.

---

## Task 2 — DAST Analysis with Multiple Tools

### 2.1 Authenticated vs Unauthenticated ZAP Scans

The unauthenticated ZAP scan discovered **95 URLs** and reported **26 alerts**: **0 High, 4 Medium, 10 Low, 12 Informational**. This baseline scan reflects the public attack surface of the application.

The authenticated ZAP run discovered significantly more surface through crawling: **112 URLs** via the standard spider and **545 URLs** via the AJAX spider. This is a major increase compared with the unauthenticated baseline, which confirms that authenticated scanning exposes much more of the application’s runtime surface.

Although the helper comparison script initially reported `0` alerts for the authenticated scan, the actual `report-auth.html` shows that the authenticated report contains **1 High, 4 Medium, 4 Low, and 3 Informational alerts**. The report also indicates **103 total endpoints** and **100% authentication failures**, so the scan still traversed a broader dynamic surface, but authentication verification was not fully successful in this run.

### 2.2 Key Authenticated Findings from ZAP

The most important authenticated ZAP finding was **SQL Injection (High)** with **2 instances**. ZAP flagged both:
- `GET /rest/products/search?q=...` with injectable parameter `q`
- `POST /rest/user/login` with injectable parameter `email`

In both cases, ZAP observed `HTTP/1.1 500 Internal Server Error` as evidence, which is a strong runtime signal of potentially unsafe query handling.

The authenticated report also identified several **Medium** issues:
- **Content Security Policy (CSP) Header Not Set**
- **Cross-Domain Misconfiguration**
- **Missing Anti-clickjacking Header**
- **Session ID in URL Rewrite**

Example runtime/session issue:
- `Session ID in URL Rewrite` was reported on Socket.IO URLs containing a `sid` parameter in the query string. This matters because session identifiers in URLs can leak via browser history, logs, and referer headers.

Example header/configuration issue:
- `Missing Anti-clickjacking Header` was reported on Socket.IO responses, meaning the application does not consistently protect pages/responses against framing-based UI attacks.

### 2.3 Multi-Tool Comparison

| Tool | Findings | Severity Breakdown | Best Use Case |
|---|---:|---|---|
| ZAP (auth report HTML) | 12 | High:1 Med:4 Low:4 Info:3 | Runtime web app assessment, crawler-driven discovery, active/passive testing |
| ZAP (noauth) | 26 | High:0 Med:4 Low:10 Info:12 | Public attack surface baseline |
| Nuclei | 0 | n/a | Fast template-based checks for known issues/CVEs |
| Nikto | 14 | n/a | Server misconfiguration, headers, default files |
| SQLmap | 1 | n/a | Targeted SQL injection validation and exploitation |

The automated summary script recorded `0` for authenticated ZAP because it parsed the wrong or empty report path during execution. However, the actual authenticated HTML report is the stronger source of truth and shows non-zero findings. Nuclei produced **0 matches**, Nikto found **14 server issues**, and SQLmap confirmed **1 SQL injection vulnerability** in its CSV output.

### 2.4 Tool-Specific Strengths

- **ZAP** was the most comprehensive DAST tool. It discovered runtime vulnerabilities such as SQLi, missing security headers, session management issues, and broader application behavior.
- **Nuclei** is best for quick template-driven checks, but in this run it did not identify any matching issues.
- **Nikto** was useful for server-side and HTTP-level problems, reporting **14 server issues**.
- **SQLmap** provided the strongest targeted validation for database injection by confirming **1 SQL injection vulnerability**, which complements both ZAP’s runtime signal and Semgrep’s source-level findings.

---

## Task 3 — SAST vs DAST Correlation

### 3.1 Total Findings Comparison

- **SAST (Semgrep): 25 findings**
- **DAST summary script total:** ZAP(auth) `0` + Nuclei `0` + Nikto `14` + SQLmap `1` = **15**
- **DAST using actual authenticated ZAP HTML instead of broken summary:** ZAP(auth) `12` + Nuclei `0` + Nikto `14` + SQLmap `1` = **27**

The difference between the script-generated DAST count and the actual authenticated ZAP report comes from report parsing, not from the scan itself. For the analysis below, the actual report evidence is more reliable than the intermediate broken summary.

### 3.2 Vulnerability Types Found Mainly by SAST

SAST was especially effective at identifying vulnerabilities that exist directly in source code:

1. **ORM/SQL injection patterns in source files**  
   Semgrep repeatedly flagged tainted input flowing into Sequelize query construction. This is visible in multiple `.ts` files and in `routes/login.ts`.

2. **Unsafe implementation details before deployment**  
   Static analysis can identify dangerous coding patterns even when they are not yet reached during testing or are protected by app flow constraints. This makes it ideal for catching defects earlier in CI/CD.

3. **Exact file-and-line developer remediation points**  
   Semgrep gives developers direct remediation locations, which DAST cannot provide.

### 3.3 Vulnerability Types Found Mainly by DAST

DAST revealed issues that are only visible when the application is running:

1. **HTTP header and browser security misconfiguration**  
   Missing CSP, missing anti-clickjacking protection, and missing `X-Content-Type-Options` are runtime response problems that static code scans often miss.

2. **Session management issues**  
   `Session ID in URL Rewrite` was only visible during runtime interaction with Socket.IO/session-related flows.

3. **Observed runtime exploitability signals**  
   ZAP and SQLmap both surfaced SQL injection at runtime. ZAP showed concrete payloads and server error evidence, while SQLmap confirmed one SQLi vulnerability from the live target.

### 3.4 Why SAST and DAST Find Different Things

SAST and DAST answer different questions:

- **SAST** asks: *“Is the code written in a dangerous way?”*  
  It works before deployment and is best for spotting insecure patterns, taint flows, and exact source locations.

- **DAST** asks: *“What is actually exposed or exploitable when the application runs?”*  
  It is better for headers, cookies, session handling, authentication behavior, routing, and real HTTP responses.

This lab clearly shows why both are needed. Semgrep found many code-level SQLi patterns, while runtime tools exposed header misconfigurations, session issues, and live SQLi behavior. Together they provide much better coverage than either method alone.

---

## Security Recommendations

1. **Fix SQL injection risks first**  
   Replace dynamic or unsafe query construction with parameterized queries and validate all user-controlled input on the server side.

2. **Harden HTTP security headers**  
   Add `Content-Security-Policy`, `X-Frame-Options` or `frame-ancestors`, and `X-Content-Type-Options` consistently across responses.

3. **Remove session identifiers from URLs**  
   Session IDs should be stored in secure cookies rather than query parameters to reduce leakage risk.

4. **Use both SAST and DAST in the DevSecOps pipeline**  
   - Run **Semgrep** in pull requests / CI for early developer feedback.
   - Run **ZAP** in QA/staging for runtime coverage.
   - Use **Nikto** for deployment/server checks.
   - Use **SQLmap** for targeted validation when injection is suspected.

---

## Final Conclusion

This lab demonstrates that **SAST and DAST are complementary, not interchangeable**. Semgrep identified **25 code-level findings**, mostly related to SQL injection patterns in the source code, while runtime tools identified live application risks such as SQL injection, security header weaknesses, session exposure, and server misconfiguration. Authenticated crawling also expanded discovered surface from **95 public URLs** to **112 spider URLs** and **545 AJAX URLs**, confirming the value of authenticated scanning even though authentication verification itself was imperfect in this run.

The main practical takeaway is simple: use **Semgrep early**, use **ZAP/Nikto/SQLmap later**, and treat correlation between static and dynamic findings as the strongest basis for prioritizing remediation.
