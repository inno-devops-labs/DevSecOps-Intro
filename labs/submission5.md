## Task 1

### SAST Tool Effectiveness

> What types of vulnerabilities did `Semgrep` detect?

- Potential SQL injection via a sequelize statement
	- 5
- Potential JS handlers injection via an unquoted template variable (leads to XSS injections)
	- 4
- Hardcoded JWT token
	- 1
- Potential XSS injection via manually constructed HTML
	- 2
- Potential path traversal via filename input
	- 4 + 4 (directory listing/indexing)
- Potential injection of redirection link
	- 2
- Eval usage
	- 1

> Evaluate coverage

Scanned 1014 files tracked by git, running 140 out of 672 code rules. Parsed ~99.9% lines. Identified 25 findings. Skipped scanning 8 files over 1 MB and 139 files that match `.semgrepignore`. 

### Critical Vulnerability Analysis

> List **5 most critical findings** from Semgrep results

| Name                            | Vulnerability Type    | Path and line                                          | Severity                                                                              |
| ------------------------------- | --------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| code-string-concat              | Code injection        | `/src/routes/userProfile.ts`, 62                       | Will likely result in full compromise of confidentiality, integrity, and availability |
| express-open-redirect           | Link injection        | `/src/routes/redirect.ts`, 19                          | Partial compromise of confidentiality                                                 |
| express-sequelize-injection     | SQL injection         | `/src/data/static/codefixes/dbSchemaChallenge_1.ts`, 5 | Could result in full compromise of confidentiality, integrity, and availability       |
| express-check-directory-listing | Path traversal        | `/src/server.ts`, 277                                  | Could result in full compromise of confidentiality, integrity, and availability       |
| raw-html-format                 | JS handlers injection | `/src/routes/chatbot.ts`, 197                          | Partial compromise of confidentiality and integrity                                   |

Note: all SQL injections are roughly identical in the level of danger since any of them can be manipulated with `UNION` to access any data. Thus, only one is shown. Similarly, other vulnerabilities of same type are only shown once.

## Task 2

### Authenticated vs Unauthenticated Scanning

**Note:** `scripts` directory mentioned in the lab is absent from the repository, commit history, and other branches. Due to limited timing, I recreated the critical scripts and performed manual analysis instead of attempting to recreate the others.

> Compare URL discovery count 

- **Zap**
	- 2 high
	- 48 medium
	- 40 low
	- 19 informational
	- 109 total
- **Nuclei**
	- 3 findings
- **Nikto**
	- 72 potential vulnerabilities
- **SQLMap**
	- 1 potential injection point

> List examples of admin/authenticated endpoints discovered

- Configuration endpoint `http://localhost:3000/rest/admin/application-configuration` was discovered to expose a private IP.

> Explain why authenticated scanning matters for security testing

Many modern web services provide a significant fraction of functionality only to authenticated users. Thus, scanning only those endpoints that are available without authentication would leave out the most important endpoints, defeating the purpose of DAST.

### Tool Comparison Matrix

| Tool   | Findings                                                                   | Severity Breakdown      | Best Use Case                                                                                             |
| ------ | -------------------------------------------------------------------------- | ----------------------- | --------------------------------------------------------------------------------------------------------- |
| ZAP    | SQL injection, web misconfigurations                                       | high, medium, low, info | Deep scanning of complex systems when a high degree of automation and customization is required           |
| Nuclei | DNS Rebinding Attack, Public Swagger API, Missing Subresource Integrity    | medium, high            | Regular high-speed scanning of big systems  (e.g. as a stage of a CI/CD pipeline)                         |
| Nikto  | Publicly available sensitive files, missing/misconfigured security headers | high, medium, low       | Quick pre-deployment configuration and compliance checks                                                  |
| SQLMap | SQL injection                                                              | high                    | Targeted SQL injection testing for SQL-heavy applications or applications managing critical data with SQL |


### Tool-Specific Strengths

> Describe what each tool excels at

- **ZAP**: comprehensive scanning, customization for authenticated scans, customizability with APIs, advanced UI, 
	- Findings
		- Example 1: SQL injection in search endpoint
		- Example 2: missing `Content Security Policy` header
- **Nuclei**: speed, identification of CVEs, reported low false positives
	- Findings
		- Example 1: DNS rebinding attack
		- Example 2: public swagger API
- **Nikto**: speed, misconfiguration identification, scanning legacy software
	- Findings
		- Example 1: publicly available `.htpasswd` file
		- Example 2: missing `Strict-Transport-Security` header
- **SQLmap**: targeted SQL injection testing
	- Findings
		- Example 1: SQL injection in search endpoint
