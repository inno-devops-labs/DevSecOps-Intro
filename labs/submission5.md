# Lab 5 — Security Analysis: SAST & DAST of OWASP Juice Shop

Student: v.galkin@innopolis.university

## Environment

- OS: Windows + PowerShell
- Docker: Docker Desktop with Linux containers
- Target application: OWASP Juice Shop v19.0.0
- Target URL: http://127.0.0.1:3000
- SAST tool: Semgrep
- DAST tools: OWASP ZAP, Nuclei, Nikto, SQLmap

## Task 1 — Static Application Security Testing with Semgrep

### SAST setup

I cloned the OWASP Juice Shop v19.0.0 source code and scanned it with Semgrep using the following rulesets:

- p/security-audit
- p/owasp-top-ten

Evidence files:

- labs/lab5/semgrep/semgrep-results.json
- labs/lab5/semgrep/semgrep-report.txt
- labs/lab5/analysis/sast-analysis.txt
- labs/lab5/analysis/semgrep-top-findings.tsv
- labs/lab5/analysis/semgrep-top-findings.csv

### SAST tool effectiveness

Semgrep was effective for identifying source-code-level security risks before deployment. It detected SQL injection patterns, path traversal patterns, hardcoded secrets, raw HTML/XSS-related patterns, unsafe template attributes, and CI/CD shell injection risk.

Scan coverage:

- Total findings: 26
- Files with findings: 21
- Targets scanned: 1014
- Rules run: 140
- Parsed lines: approximately 99.9%
- Severity breakdown: 8 ERROR, 18 WARNING

### Five most critical Semgrep findings

| # | Type | Severity | File / Line | Why it matters |
|---|------|----------|-------------|----------------|
| 1 | GitHub Actions shell injection | ERROR | /src/.github/workflows/update-challenges-ebook.yml:21 | Untrusted GitHub context data in a run step can lead to command injection in CI and possible secret theft. |
| 2 | SQL injection / Sequelize injection | ERROR | /src/routes/login.ts:34 | User-controlled input reaches a Sequelize statement, which can lead to SQL injection if not parameterized. |
| 3 | SQL injection / Sequelize injection | ERROR | /src/data/static/codefixes/dbSchemaChallenge_1.ts:5 | Demonstrates unsafe query construction with tainted input. |
| 4 | Hardcoded JWT secret | WARNING | /src/lib/insecurity.ts:56 | Hardcoded secrets in source code can be leaked and reused by attackers. |
| 5 | Path traversal via sendFile | WARNING | /src/routes/fileServer.ts:33 | User input reaches res.sendFile, which may allow arbitrary file reads without strict validation and canonicalization. |

Additional notable findings:

- Raw HTML construction in /src/routes/chatbot.ts:197, which can lead to XSS.
- Unquoted Angular template attributes in frontend templates.
- Multiple Express sendFile patterns in keyServer, logfileServer, quarantineServer, and fileServer routes.

## Task 2 — Dynamic Application Security Testing with Multiple Tools

### Target setup

I ran OWASP Juice Shop v19.0.0 locally:

`	ext
docker run -d --name juice-shop-lab5 -p 3000:3000 bkimminich/juice-shop:v19.0.0
`

The application was reachable at:

`	ext
http://127.0.0.1:3000
`

Evidence:

- labs/lab5/analysis/login-test-raw-fixed.txt

The login endpoint was validated with the default Juice Shop admin account and returned HTTP 200 with a JWT token.

### OWASP ZAP unauthenticated vs authenticated scanning

Unauthenticated baseline scan:

- Discovered 95 URLs
- Evidence:
  - labs/lab5/zap/report-noauth.html
  - labs/lab5/zap/zap-report-noauth.json
  - labs/lab5/analysis/zap-noauth-console.txt

Authenticated ZAP Automation Framework scan:

- Traditional spider discovered 112 URLs
- AJAX spider discovered 615 URLs
- Active scan completed successfully
- Automation plan succeeded
- Evidence:
  - labs/lab5/zap/report-auth.html
  - labs/lab5/zap/zap-report-auth.json
  - labs/lab5/analysis/zap-auth-console.txt
  - labs/lab5/scripts/zap-auth.yaml

Authenticated scanning matters because it reaches a much larger attack surface than anonymous scanning. In this run, the unauthenticated baseline discovered 95 URLs, while the authenticated AJAX spider discovered 615 URLs. This means authenticated scanning can exercise user-specific and admin/application functionality that anonymous scanning does not reach.

### DAST tool comparison matrix

| Tool | Findings / Coverage | Severity breakdown / result | Best use case |
|------|---------------------|-----------------------------|---------------|
| ZAP unauthenticated | 95 URLs discovered | Baseline passive web findings saved in no-auth report | Quick public attack surface scan |
| ZAP authenticated | 112 spider URLs and 615 AJAX spider URLs; active scan completed | Auth report generated successfully | Comprehensive authenticated web application scanning |
| Nuclei | 0 template matches | No template matches in this local scan | Fast known-CVE and template-based checks |
| Nikto | 162 reported server findings/items | Includes missing X-XSS-Protection, wildcard CORS, /ftp/ in robots.txt, and many interesting backup/cert paths | Web server misconfiguration and exposed file checks |
| SQLmap | 1 confirmed SQL injection on search endpoint | Boolean-based blind SQL injection, backend DBMS SQLite | Deep SQL injection detection and exploitation validation |

### Tool-specific strengths

#### ZAP

ZAP is strongest for general web application scanning, crawling, authenticated testing, passive scanning, and active scanning. The authenticated scan discovered a larger attack surface than the unauthenticated scan.

Example evidence:

- Unauthenticated scan: 95 URLs
- Authenticated scan: 112 traditional spider URLs
- Authenticated AJAX spider: 615 URLs
- Active scan completed

#### Nuclei

Nuclei is strongest for fast template-based checks against known CVEs, exposures, and common misconfigurations. In this local Juice Shop scan, it produced 0 template matches. This is still useful evidence: no matching templates were triggered in this environment.

#### Nikto

Nikto is strongest for web server misconfiguration checks and known exposed file/path checks.

Example findings:

- Access-Control-Allow-Origin: *
- X-XSS-Protection header is not defined
- /ftp/ exposed through robots.txt
- Potential backup/cert paths such as .jks, .tar, .tgz, .pem, .cer, and .war patterns

#### SQLmap

SQLmap is strongest for targeted SQL injection validation. It confirmed SQL injection on the search endpoint:

`	ext
/rest/products/search?q=*
`

Evidence from the scan:

`	ext
URI parameter '#1*' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
URI parameter '#1*' is vulnerable
back-end DBMS: SQLite
`

The login endpoint was also tested. After fixing the PowerShell JSON escaping issue, the login endpoint returned a valid JWT with curl. SQLmap login testing was recorded in sqlmap-login-console.txt, but the confirmed SQL injection evidence in this submission comes from the search endpoint.

## Task 3 — SAST/DAST Correlation and Security Assessment

### SAST vs DAST comparison

SAST findings:

- Semgrep: 26 findings across 21 files
- Severity: 8 ERROR and 18 WARNING

DAST findings:

- ZAP authenticated alert types: 13
- Nuclei template matches: 0
- Nikto reported findings/items: 162
- SQLmap confirmed SQL injection vulnerabilities: 1

### Vulnerability types found only or mainly by SAST

1. Hardcoded secrets:
   - Semgrep detected a hardcoded JWT secret in /src/lib/insecurity.ts.
   - This is easier to detect in source code than through black-box runtime testing.

2. CI/CD shell injection:
   - Semgrep detected unsafe GitHub Actions variable interpolation.
   - This is a source repository / pipeline risk, not a web runtime endpoint.

3. Code-level path traversal patterns:
   - Semgrep detected user input reaching res.sendFile.
   - DAST may or may not reach the exact path and payload combination, but SAST can flag the risky code pattern early.

### Vulnerability types found only or mainly by DAST

1. Runtime HTTP header issues:
   - Nikto identified missing X-XSS-Protection and wildcard CORS behavior.
   - These depend on actual HTTP responses.

2. Exposed runtime paths:
   - Nikto found /ftp/ in robots.txt and many potentially interesting backup/cert path patterns.
   - These are deployment/runtime exposure checks.

3. Confirmed exploitability:
   - SQLmap dynamically confirmed SQL injection on the search endpoint and identified SQLite as the backend DBMS.
   - This goes beyond static suspicion and validates runtime exploitability.

4. Authenticated attack surface:
   - ZAP authenticated scanning found a much larger dynamic URL surface through AJAX spidering.
   - This requires a running application and session context.

### Why SAST and DAST find different things

SAST analyzes source code and can identify risky patterns before the application is deployed. It is good for early feedback in development and CI pipelines. However, SAST may produce false positives because it does not always know the runtime context.

DAST tests a running application. It can discover runtime configuration issues, authentication-dependent attack surface, exposed paths, and actual exploitability. However, DAST may miss vulnerabilities hidden in code paths that are hard to reach dynamically.

The best DevSecOps approach is to use both. Semgrep provides early code-level security feedback, while ZAP, Nuclei, Nikto, and SQLmap validate the running application from an attacker's perspective.

## Evidence files

### SAST

- labs/lab5/semgrep/semgrep-results.json
- labs/lab5/semgrep/semgrep-report.txt
- labs/lab5/analysis/sast-analysis.txt
- labs/lab5/analysis/semgrep-top-findings.tsv
- labs/lab5/analysis/semgrep-top-findings.csv

### DAST

- labs/lab5/zap/report-noauth.html
- labs/lab5/zap/zap-report-noauth.json
- labs/lab5/zap/report-auth.html
- labs/lab5/zap/zap-report-auth.json
- labs/lab5/analysis/zap-noauth-console.txt
- labs/lab5/analysis/zap-auth-console.txt
- labs/lab5/analysis/zap-comparison.txt
- labs/lab5/analysis/zap-alert-summary.txt
- labs/lab5/nuclei/nuclei-results.json
- labs/lab5/analysis/nuclei-console.txt
- labs/lab5/nikto/nikto-results.txt
- labs/lab5/analysis/nikto-console.txt
- labs/lab5/analysis/sqlmap-search-console.txt
- labs/lab5/analysis/sqlmap-login-console.txt
- labs/lab5/sqlmap/login-request.txt
- labs/lab5/analysis/dast-summary.txt

### Correlation

- labs/lab5/analysis/correlation.txt

## Recommendations

1. Replace unsafe SQL query construction with parameterized queries or ORM-safe query APIs.
2. Remove hardcoded secrets and load secrets from environment variables or a secrets manager.
3. Validate and canonicalize file paths before using res.sendFile.
4. Avoid constructing raw HTML with user-controlled data; sanitize output or use safe templating.
5. Add or review security headers, including modern XSS, CSP, and CORS policies.
6. Restrict public access to sensitive folders such as /ftp/ and remove unnecessary files from public web roots.
7. Run Semgrep in CI for early detection and run ZAP/SQLmap in staging for runtime validation.
8. Use authenticated DAST scans because they reveal significantly more application behavior than anonymous scans.

## Conclusion

This lab demonstrates that SAST and DAST provide complementary security coverage. Semgrep found source-code-level risks such as SQL injection patterns, hardcoded secrets, path traversal patterns, and CI/CD shell injection. ZAP, Nikto, Nuclei, and SQLmap tested the running application and revealed runtime behavior, exposed attack surface, server configuration issues, and confirmed SQL injection exploitability.

The strongest security workflow is to combine SAST in the development pipeline with authenticated DAST and specialized tools in staging or test environments.
