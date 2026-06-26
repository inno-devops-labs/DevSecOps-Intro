# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- Duration: **~1-2 minutes**. Exact shell timer was not captured for this run.
- Total alerts: **10**

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan

- Duration: **518 seconds** (~8 min 38 sec)
- Total alerts: **12**

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)

- Ratio (auth alerts / baseline alerts): **1.2×** (`12 / 10`)

My run did not match the lecture's 10–20× example. The authenticated scan found more alert types than the baseline scan, including one High severity alert, but the increase was much smaller than 10×. This likely happened because the baseline scan already reached many unauthenticated Juice Shop routes, while the authenticated automation was limited by the provided crawl and active-scan duration settings. The exact ratio also depends on ZAP rule versions, crawler coverage, scan depth, and application state.

### Two authenticated-only alerts

1. **SQL Injection** — High (Low)
   - Plugin ID: `40018`
   - Count: `2`
   - Sample URI: `http://juice-shop:3000/rest/products/search?q=%27%28`
   - Parameter: `q`
   - Why baseline could not reach it: The authenticated scan used a deeper crawl plus active scan plan and reached the search endpoint with an injection payload, while the unauthenticated baseline did not report this active SQL injection finding.

2. **Private IP Disclosure** — Low (Medium)
   - Plugin ID: `2`
   - Count: `1`
   - Sample URI: `http://juice-shop:3000/rest/admin/application-configuration`
   - Why baseline could not reach it: This is an admin/application-configuration route discovered during the authenticated crawl, so it was not part of the unauthenticated baseline findings.

Other authenticated-only findings included `Missing Anti-clickjacking Header`, `Session ID in URL Rewrite`, `X-Content-Type-Options Header Missing`, `Authentication Request Identified`, `Session Management Response Identified`, and `User Agent Fuzzer`.

---

## Task 2: SAST with Semgrep

### Source pinning

Semgrep was run against the Juice Shop source cloned with the same tag as the running container:

```text
v20.0.0
```

This keeps the SAST source code aligned with the DAST target image `bkimminich/juice-shop:v20.0.0`.

### Semgrep severity breakdown

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | **22** |

### Top 10 rules by frequency

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 Injection / CI command injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01 Broken Access Control / path traversal |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

### Triage shortcut

If I had time to fix only one Semgrep rule first, I would pick:

```text
javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
```

Reason: this rule has the highest frequency in the Semgrep results, appears with `ERROR` severity, maps to OWASP A03 Injection, and directly correlates with the ZAP SQL Injection alert. This makes it the strongest first fix because it is supported by both static evidence from source code and dynamic evidence from the running application.

### False-positive sample

- File path: `.github/workflows/update-challenges-www.yml:27`
- Rule: `yaml.github-actions.security.run-shell-injection.run-shell-injection`

I would suppress or deprioritize this finding for the Lab 5 web-application triage because it is CI workflow code from the upstream repository, not a runtime Juice Shop endpoint reachable by ZAP in the running container. It may still matter for repository security, but it is not directly correlated with the running web application attack surface tested in this lab.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP category | ZAP alert | ZAP URI / parameter | Semgrep rule | Semgrep file:line | Confidence |
|---|----------------|-----------|---------------------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q=%27%28`, parameter `q` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/search.ts:23` | High: both tools report SQL injection on the same search functionality |

### Strongest correlation deep-dive

#### Vulnerable code from Semgrep file:line

File: `routes/search.ts:21-23`

```ts
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

The vulnerable data flow is:

```text
req.query.q → criteria → string interpolation inside models.sequelize.query(...)
```

The length limit only truncates the input to 200 characters. It does not make the SQL query safe because the user-controlled value is still inserted directly into the SQL string.

#### Working payload from ZAP report

ZAP authenticated scan reported:

```text
Alert: SQL Injection
Risk: High (Low)
Plugin: 40018
URI: http://juice-shop:3000/rest/products/search?q=%27%28
Parameter: q
Attack: '(
Evidence: HTTP/1.1 500 Internal Server Error
```

ZAP also reported a second SQL injection instance on the login endpoint:

```text
URI: http://juice-shop:3000/rest/user/login
Parameter: email
Attack: '
Evidence: HTTP/1.1 500 Internal Server Error
```

#### Proposed fix

The fix is to stop building SQL with string interpolation and use parameterized queries or Sequelize query bindings. Input length limits can remain as defense-in-depth, but they do not replace parameterization.

Example direction:

```ts
const likeCriteria = `%${criteria}%`

models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE ? OR description LIKE ?) AND deletedAt IS NULL) ORDER BY name',
  { replacements: [likeCriteria, likeCriteria] }
)
```

This prevents the value of `criteria` from being interpreted as SQL syntax.

#### Why both tools caught it

Semgrep caught the issue statically because it saw request-controlled data from `req.query.q` flowing into a raw Sequelize SQL query. ZAP caught it dynamically because it sent an SQL injection payload to the running endpoint and observed an internal server error response, showing that the input affected SQL execution.

### Reflection

In a real PR review, I would want both pieces of evidence. The Semgrep result is useful because it points directly to the vulnerable file and line, which makes remediation faster. The ZAP result is useful because it proves the issue is reachable and observable in the running application. Together, they form a high-confidence finding because the same weakness is visible from both the code and runtime behavior.
