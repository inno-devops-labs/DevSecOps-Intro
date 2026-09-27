# Lab 5 — Security Scanning and Static Analysis

## 1. Objective

The objective of this laboratory work was to perform security analysis of the OWASP Juice Shop application using dynamic application security testing (DAST) and static application security testing (SAST).

The analysis included:

* authenticated and baseline OWASP ZAP scans;
* comparison of security findings between unauthenticated and authenticated scans;
* static analysis of the Juice Shop source code using Semgrep;
* investigation of selected high-severity findings;
* identification of SQL injection and CI/CD security issues;
* analysis of the relationship between scanner findings and the corresponding source code.

The tested application was OWASP Juice Shop version `v20.0.0`.

---

## 2. OWASP ZAP Results

Two ZAP reports were analyzed:

* `labs/lab5/results/baseline-report.json`
* `labs/lab5/results/auth-report.json`

The baseline scan was performed without authentication, while the authenticated scan included access to authenticated application functionality.

### 2.1 Baseline scan

The baseline report contained the following alerts:

| Risk              | Alert                                                  | Example URI                                           |
| ----------------- | ------------------------------------------------------ | ----------------------------------------------------- |
| Medium (2)        | Content Security Policy (CSP) Header Not Set           | `http://juice-shop:3000`                              |
| Medium (2)        | Cross-Domain Misconfiguration                          | `http://juice-shop:3000/assets/public/favicon_js.ico` |
| Low (1)           | Cross-Origin-Embedder-Policy Header Missing or Invalid | `http://juice-shop:3000`                              |
| Low (1)           | Cross-Origin-Opener-Policy Header Missing or Invalid   | `http://juice-shop:3000`                              |
| Low (1)           | Dangerous JS Functions                                 | `http://juice-shop:3000/main.js`                      |
| Low (1)           | Deprecated Feature Policy Header Set                   | `http://juice-shop:3000`                              |
| Informational (0) | Modern Web Application                                 | `http://juice-shop:3000`                              |
| Informational (0) | Storable and Cacheable Content                         | `http://juice-shop:3000/robots.txt`                   |
| Informational (0) | Storable but Non-Cacheable Content                     | `http://juice-shop:3000`                              |

The baseline scan therefore identified several missing or incorrectly configured security headers, as well as other low-risk findings.

---

## 3. Authenticated ZAP Scan

The authenticated scan produced a larger set of findings.

The most important findings were:

| Risk          | Alert                                        | Example URI                                            |
| ------------- | -------------------------------------------- | ------------------------------------------------------ |
| High (3)      | SQL Injection                                | `http://juice-shop:3000/rest/products/search?q=%27%28` |
| High (3)      | Vulnerable JS Library                        | `http://juice-shop:3000/chunk-GJJPXCX3.js`             |
| Medium (2)    | Content Security Policy (CSP) Header Not Set | `http://juice-shop:3000`                               |
| Medium (2)    | Cross-Domain Misconfiguration                | `http://juice-shop:3000`                               |
| Medium (2)    | Missing Anti-clickjacking Header             | `http://juice-shop:3000/socket.io/...`                 |
| Medium (2)    | Session ID in URL Rewrite                    | `http://juice-shop:3000/socket.io/...`                 |
| Low (1)       | Private IP Disclosure                        | `/rest/admin/application-configuration`                |
| Low (1)       | Timestamp Disclosure - Unix                  | `http://juice-shop:3000`                               |
| Low (1)       | X-Content-Type-Options Header Missing        | `http://juice-shop:3000/socket.io/...`                 |
| Informational | Authentication Request Identified            | `/rest/user/login`                                     |
| Informational | Modern Web Application                       | `http://juice-shop:3000`                               |
| Informational | Session Management Response Identified       | `/rest/user/login`                                     |
| Informational | User Agent Fuzzer                            | `/socket.io/...`                                       |

The authenticated scan therefore detected additional security issues that were not present in the baseline scan.

---

## 4. Comparison of Baseline and Authenticated Scans

The most significant difference between the two scans is the appearance of application-level vulnerabilities after authenticated scanning.

The baseline scan detected mainly security-header and configuration issues. In contrast, the authenticated scan additionally detected:

* SQL Injection;
* Vulnerable JavaScript Library;
* Missing Anti-clickjacking Header;
* Session ID in URL Rewrite;
* Private IP Disclosure;
* Timestamp Disclosure;
* missing `X-Content-Type-Options`.

The SQL Injection finding is particularly important because it points to the `/rest/products/search` endpoint:

```text
/rest/products/search?q=%27%28
```

This endpoint accepts the `q` parameter and is connected to the `searchProducts()` function in the Juice Shop source code.

The comparison demonstrates that authenticated scanning can expose vulnerabilities that are not necessarily reachable or detectable during a basic unauthenticated scan.

---

# 5. Semgrep Static Analysis

Static analysis was performed on the Juice Shop `v20.0.0` source code.

The source code was placed in:

```text
labs/lab5/semgrep/juice-shop
```

The Semgrep results were saved to:

```text
labs/lab5/results/semgrep.json
```

The Semgrep result file contained:

* 27 findings;
* 13 findings with `ERROR` severity;
* 14 findings with `WARNING` severity.

The most frequently reported rules were:

| Findings | Rule                                                                                                |
| -------: | --------------------------------------------------------------------------------------------------- |
|        6 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`       |
|        5 | `yaml.github-actions.security.run-shell-injection.run-shell-injection`                              |
|        4 | `javascript.express.security.audit.express-res-sendfile.express-res-sendfile`                       |
|        4 | `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` |
|        4 | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag`  |
|        1 | `javascript.lang.security.audit.code-string-concat.code-string-concat`                              |
|        1 | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret`                                |
|        1 | `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell`                              |
|        1 | `javascript.express.security.audit.express-open-redirect.express-open-redirect`                     |

---

# 6. SQL Injection Detected by Semgrep

One of the most important Semgrep findings is the Sequelize SQL injection rule:

```text
javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
```

The rule produced six findings.

Four findings are located in Juice Shop challenge code under:

```text
data/static/codefixes/
```

Two findings are located in actual application routes:

```text
routes/login.ts:34
routes/search.ts:23
```

The finding in `routes/search.ts` is especially relevant because it corresponds to the SQL Injection vulnerability identified by ZAP.

The relevant source code is:

```typescript
export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)

    models.sequelize.query(
      `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
    )
```

The problem is that the value of `criteria` originates from the HTTP request:

```text
req.query.q
```

and is then directly inserted into an SQL query using string interpolation:

```typescript
`... LIKE '%${criteria}%' ...`
```

Therefore, the application constructs an SQL statement using user-controlled input rather than passing the value as a parameter.

Semgrep explicitly reports that this can lead to SQL injection and recommends parameterized queries or prepared statements.

This finding is also independently confirmed by the ZAP authenticated scan:

```text
SQL Injection
Risk: 3 (High)
URI:
http://juice-shop:3000/rest/products/search?q=%27%28
```

Thus, the DAST and SAST results identify the same underlying vulnerability from two different perspectives:

* ZAP detects the vulnerability while interacting with the running application.
* Semgrep detects the unsafe construction directly in the source code.

---

# 7. GitHub Actions Security Findings

Semgrep also identified several security issues in the GitHub Actions workflows.

### 7.1 Mutable GitHub Action references

The rule:

```text
yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag
```

reported four findings.

They occur in:

```text
.github/workflows/ci.yml:202
.github/workflows/codeql-analysis.yml:23
.github/workflows/codeql-analysis.yml:34
.github/workflows/codeql-analysis.yml:36
```

The issue is that GitHub Actions can reference mutable tags or branches instead of immutable commit SHAs.

A mutable reference can change after the workflow has been reviewed. Pinning an action to a full commit SHA makes the dependency immutable and reduces the risk of a supply-chain compromise.

---

### 7.2 `curl | shell` pattern

Semgrep identified one `ERROR` finding:

```text
yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell
```

Location:

```text
.github/workflows/ci.yml:372
```

The rule detects a workflow step that pipes the output of `curl` or `wget` directly into a shell interpreter.

This pattern is potentially dangerous because code retrieved from a remote location is executed directly by the CI runner.

A safer approach is to:

1. download the file;
2. verify its checksum or signature;
3. execute the verified file.

---

### 7.3 GitHub context interpolation in shell commands

Semgrep identified five findings for:

```text
yaml.github-actions.security.run-shell-injection.run-shell-injection
```

The findings occur in:

```text
.github/workflows/update-challenges-ebook.yml:22
.github/workflows/update-challenges-www-legacy.yml:27
.github/workflows/update-challenges-www-legacy.yml:36
.github/workflows/update-challenges-www.yml:27
.github/workflows/update-challenges-www.yml:36
```

The problem is interpolation of `${{ ... }}` GitHub context data directly into `run:` commands.

The Semgrep rule treats GitHub context data as potentially untrusted input and recommends placing the value into an environment variable before using it in the shell command.

---

# 8. Other Semgrep Findings

Additional findings included:

### Hardcoded JWT secret

```text
javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret
```

Location:

```text
lib/insecurity.ts:56
```

Severity:

```text
WARNING
```

### `res.sendFile` security issues

The following files were reported:

```text
routes/fileServer.ts:33
routes/keyServer.ts:14
routes/logfileServer.ts:14
routes/quarantineServer.ts:14
```

Rule:

```text
javascript.express.security.audit.express-res-sendfile.express-res-sendfile
```

### Open redirect

Location:

```text
routes/redirect.ts:19
```

Rule:

```text
javascript.express.security.audit.express-open-redirect.express-open-redirect
```

### Directory listing

Four findings were reported in:

```text
server.ts:269
server.ts:273
server.ts:277
server.ts:281
```

Rule:

```text
javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing
```

---

# 9. Relationship Between DAST and SAST

The results demonstrate the complementary nature of DAST and SAST.

DAST analyzes the running application and identifies vulnerabilities through HTTP requests and responses. In this laboratory, ZAP detected SQL Injection in:

```text
/rest/products/search
```

SAST analyzes the application source code without requiring the vulnerability to be exploited at runtime. Semgrep identified the corresponding unsafe SQL construction in:

```text
routes/search.ts:23
```

The two approaches therefore provide different types of evidence.

| Aspect                | ZAP                   | Semgrep                        |
| --------------------- | --------------------- | ------------------------------ |
| Analysis type         | DAST                  | SAST                           |
| Target                | Running application   | Source code                    |
| SQL Injection         | Detected              | Detected                       |
| Security headers      | Detected              | Generally not the main purpose |
| CI/CD vulnerabilities | Not the focus         | Detected                       |
| Source-code location  | Not directly provided | Provided                       |
| Runtime behavior      | Tested                | Not executed                   |

Using both approaches provides broader security coverage than relying on only one scanner.

---

# 10. Conclusion

The security assessment of OWASP Juice Shop v20.0.0 demonstrated several types of security issues.

The ZAP baseline scan primarily identified security-header and configuration issues. The authenticated scan additionally detected application-level vulnerabilities, including SQL Injection and a vulnerable JavaScript library.

The SQL Injection finding was investigated in the source code and independently confirmed by Semgrep. The vulnerable endpoint `/rest/products/search` passes the HTTP query parameter `q` into an SQL statement using string interpolation.

Semgrep also identified several source-code and CI/CD security issues, including:

* SQL injection;
* GitHub Actions mutable references;
* shell injection through GitHub context interpolation;
* direct `curl`/`wget` piping into a shell;
* hardcoded JWT secret;
* potentially unsafe `sendFile` usage;
* open redirect;
* directory listing.

The combined DAST and SAST analysis demonstrates why both runtime testing and source-code analysis are useful in a DevSecOps workflow. DAST can confirm vulnerabilities in a running application, while SAST can identify their source-code locations and detect additional problems that may not be exposed by a particular runtime scan.
