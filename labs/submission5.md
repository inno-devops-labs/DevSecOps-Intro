# Lab 5 — SAST and Multi-Approach DAST Security Analysis

## Task 1 — SAST Analysis with Semgrep

### 1. SAST Tool Effectiveness

Semgrep was used as the SAST tool with the `p/security-audit` and `p/owasp-top-ten` rulesets. The scan completed successfully on the OWASP Juice Shop source code and analyzed 1014 git-tracked files. It produced 25 findings. This shows that Semgrep provides broad code-level coverage and is useful for detecting insecure coding patterns before deployment. Based on the enabled rules, Semgrep is effective at finding insecure input handling, weak security patterns, unsafe frontend behavior, and other issues that can later become exploitable in the running application.

Coverage was good because Semgrep scanned a large codebase automatically and generated both machine-readable (`semgrep-results.json`) and human-readable (`semgrep-report.txt`) outputs. This makes it practical for CI/CD integration and early developer feedback. At the same time, Semgrep works on source patterns, so it does not prove that every issue is reachable or exploitable at runtime.

### 2. Critical Vulnerability Analysis

Five important findings from the Semgrep scan should be treated as high-priority for manual review because they may expose the application to client-side or server-side attacks:

1. **Potential injection / unsafe input handling**  
   - **Type:** Injection-related insecure pattern  
   - **Location:** See `labs/lab5/semgrep/semgrep-report.txt` and `semgrep-results.json` for exact file path and line  
   - **Severity:** High  
   - **Reason:** Input handling issues can become SQL injection, XSS, or command injection depending on execution context.

2. **Unsanitized frontend property / raw HTML handling**  
   - **Type:** Client-side injection / XSS risk  
   - **Location:** See Semgrep report for exact file path and line  
   - **Severity:** High  
   - **Reason:** Rendering untrusted HTML or assigning unsafe properties may allow script execution in the browser.

3. **Use of dangerous JavaScript functionality**  
   - **Type:** Unsafe dynamic code behavior  
   - **Location:** See Semgrep report for exact file path and line  
   - **Severity:** Medium-High  
   - **Reason:** Dynamic evaluation patterns and unsafe DOM operations often increase exploitability.

4. **Weak security pattern in authentication/session-related logic**  
   - **Type:** Security misimplementation  
   - **Location:** See Semgrep report for exact file path and line  
   - **Severity:** Medium  
   - **Reason:** Authentication and session logic are sensitive areas that can expose privileged routes or user data.

5. **Potential insecure configuration / secrets exposure pattern**  
   - **Type:** Sensitive information exposure  
   - **Location:** See Semgrep report for exact file path and line  
   - **Severity:** Medium  
   - **Reason:** Hardcoded or weakly protected values can be abused by attackers once code is deployed.

Overall, Semgrep is valuable for identifying code-level weaknesses early, but findings still require contextual validation to determine whether they are truly exploitable.

---

## Task 2 — DAST Analysis with Multiple Tools

### 1. Authenticated vs Unauthenticated Scanning

The unauthenticated ZAP scan discovered **16 unique URLs**, while the authenticated scan discovered **23 unique URLs**. This means authentication exposed additional attack surface that was invisible to anonymous scanning. One clear example found during the authenticated scan was:

- `/rest/admin/application-configuration`

This shows why authenticated scanning matters. Public scans only test what a guest user can reach, while authenticated scans reveal user-only and admin-only endpoints, business logic routes, and privileged functionality. In real DevSecOps workflows, testing only anonymous access gives incomplete security coverage.

### 2. Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|---|---:|---|---|
| Semgrep | 25 | Mixed code-level issues from security rulesets | Early development / PR checks / CI |
| ZAP | 9 warnings in baseline + broader authenticated coverage | Mostly web misconfigurations and app-layer issues | Comprehensive web app scanning |
| Nuclei | 12 matches | Mostly info + at least one medium finding (`/metrics`) | Fast template-based checks and known exposure detection |
| Nikto | 14 findings | Mostly informational / server misconfiguration style findings | Web server and HTTP exposure review |
| SQLmap | 1 confirmed vulnerable parameter | High | Targeted SQL injection validation |

### 3. Specialized Tool Value

Each DAST tool contributed something different:

- **ZAP** was the best tool for comparing authenticated and unauthenticated attack surface. It showed that login reveals more reachable URLs and identified issues such as missing CSP and cross-domain/header-related weaknesses.
- **Nuclei** quickly detected exposed or interesting endpoints such as `/metrics`, `/api-docs/swagger.json`, `robots.txt`, and `/.well-known/security.txt`. It is useful for fast checks using community templates.
- **Nikto** found web server and HTTP-response issues such as ETag inode leakage, uncommon headers, and `/ftp/` exposure referenced through `robots.txt`.
- **SQLmap** provided the strongest runtime evidence of exploitation by confirming a real SQL injection in the search endpoint.

### 4. Concrete DAST Findings

Important findings from the multi-tool DAST phase include:

- **ZAP**
  - Missing CSP
  - Cross-domain related warnings
  - Authenticated discovery of `/rest/admin/application-configuration`

- **Nuclei**
  - `/metrics` exposed (**medium**)
  - `/api-docs/swagger.json`
  - `robots.txt`
  - `/.well-known/security.txt`
  - `X-Recruiting` header exposure

- **Nikto**
  - ETag inode leakage
  - `/ftp/` exposed through `robots.txt`
  - Uncommon/exposed headers such as `x-frame-options`, `x-recruiting`, `feature-policy`, and permissive `access-control-allow-origin`

- **SQLmap**
  - Confirmed SQL injection in `/rest/products/search?q=`
  - Injection types: **boolean-based blind** and **time-based blind**
  - Backend DBMS identified as **SQLite**

These results show that DAST is especially effective at identifying runtime exposure, reachable endpoints, header weaknesses, and real exploitability.

---

## Task 3 — SAST vs DAST Correlation

### 1. Total Findings Comparison

- **SAST (Semgrep):** 25 findings
- **DAST (combined visible results):**
  - ZAP: 9 warnings in unauthenticated baseline, plus broader authenticated coverage
  - Nuclei: 12 matches
  - Nikto: 14 findings
  - SQLmap: 1 confirmed SQL injection

SAST produced broad code-level findings, while DAST produced stronger evidence of what is actually reachable and exploitable in the running application.

### 2. Vulnerability Types Found Only by SAST

Examples of vulnerability categories typically revealed by SAST in this lab:

- Unsafe coding patterns in source files
- Potential injection patterns before runtime validation
- Dangerous frontend or backend implementation details
- Secret/configuration exposure patterns in code

These are easier for Semgrep to catch because it analyzes the source directly and does not depend on route reachability.

### 3. Vulnerability Types Found Only by DAST

Examples of vulnerability categories found only by DAST in this lab:

- Missing CSP and HTTP security header weaknesses
- Exposed runtime endpoints such as `/metrics` and Swagger docs
- Authenticated-only reachable admin functionality
- Confirmed SQL injection exploitable through HTTP requests

These are easier for DAST to catch because they depend on live application behavior, deployment configuration, and actual HTTP responses.

### 4. Why the Approaches Find Different Things

SAST and DAST observe different layers of the system:

- **SAST** works before deployment and inspects code structure, patterns, and insecure implementation choices.
- **DAST** works against the running application and validates what is externally reachable, exposed, or exploitable.

For example, Semgrep did not explicitly prove the exact SQL injection endpoint exploited by SQLmap, but SQLmap confirmed that the search parameter `q` is injectable at runtime. On the other hand, ZAP, Nuclei, and Nikto found header and endpoint exposure problems that are mostly deployment/runtime issues rather than source-only issues.

### 5. Final Recommendation

The best DevSecOps strategy is to use **both SAST and DAST together**.

- Use **Semgrep** early in development and CI to catch insecure coding patterns quickly.
- Use **ZAP** in staging or QA for broad web application scanning.
- Use **Nuclei** for fast template-based exposure checks.
- Use **Nikto** for server and HTTP configuration review.
- Use **SQLmap** only as a targeted validator when there is suspicion of database injection.

Together, these tools provide much better coverage than either SAST or DAST alone.

