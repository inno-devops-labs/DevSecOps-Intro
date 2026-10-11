# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Environment

The target application was OWASP Juice Shop v20.0.0 running locally in Docker.

Two OWASP ZAP scans were performed:

1. An unauthenticated baseline scan
2. An authenticated scan using the provided ZAP Automation Framework configuration

The authenticated scan included the traditional spider, AJAX spider, passive scanning, and active scanning.

### Baseline unauthenticated scan

* Duration: 79 seconds
* URLs scanned: 158
* Total alert instances: 40
* Unique alert types: 10

| Severity      |  Count |
| ------------- | -----: |
| High          |      0 |
| Medium        |      8 |
| Low           |     21 |
| Informational |     11 |
| **Total**     | **40** |

### Authenticated full scan

* Duration: 352 seconds
* Traditional spider URLs: 93
* AJAX spider URLs: 490
* Total alert instances: 42
* Unique alert types: 12

| Severity      |  Count |
| ------------- | -----: |
| High          |      2 |
| Medium        |     18 |
| Low           |     11 |
| Informational |     11 |
| **Total**     | **42** |

### The “10–20× more” claim

The ratio of authenticated alert instances to baseline alert instances was:

`42 / 40 = 1.05×`

This run did not reproduce the lecture’s expected 10–20× increase. The baseline scan already discovered many public resources and passive security-header findings, while the authenticated scan increased the total number of alert instances by only 5%.

However, the severity profile changed significantly. The baseline scan found no High severity findings, while the authenticated active scan identified two High severity SQL injection findings. Therefore, authentication and active scanning improved the value of the results even though the total alert count increased only slightly.

### Alerts found only during the authenticated scan

#### 1. SQL Injection in product search

* Alert: SQL Injection
* Severity: High
* Confidence: Low
* Endpoint: `GET /rest/products/search`
* Parameter: `q`
* Test input: `'(`
* Evidence: `HTTP/1.1 500 Internal Server Error`

The baseline scan did not actively inject SQL-related payloads into this parameter. The authenticated Automation Framework scan included active scanning, which tested the endpoint with malformed input and observed an HTTP 500 response.

The HTTP 500 response alone does not prove successful exploitation, especially because ZAP assigned Low confidence. However, the behavior is consistent with unsafe SQL query construction and was later supported by the Semgrep source-code finding.

#### 2. SQL Injection in login

* Alert: SQL Injection
* Severity: High
* Confidence: Low
* Endpoint: `POST /rest/user/login`
* Parameter: `email`
* Test input: `'`
* Evidence: `HTTP/1.1 500 Internal Server Error`

The baseline scan did not submit active SQL injection payloads to the login request body. The authenticated active scan tested the `email` parameter and observed an HTTP 500 response after supplying a quote character.

This response is consistent with a malformed SQL statement, although the ZAP result remains Low confidence until manually verified.

### Other authenticated-only alert types

The following alert types also appeared only in the authenticated report:

* Missing Anti-clickjacking Header
* X-Content-Type-Options Header Missing
* User Agent Fuzzer
* Authentication Request Identified
* Session Management Response Identified
* Private IP Disclosure
* Session ID in URL Rewrite
* SQL Injection

## Task 2: SAST with Semgrep

### Environment

Semgrep 1.168.0 was used to scan the source code of OWASP Juice Shop v20.0.0.

The following rule sets were used:

* `p/owasp-top-ten`
* `p/javascript`
* `p/secrets`

The scan processed 1,000 Git-tracked files using 151 applicable rules.

### Semgrep severity breakdown

| Severity  |  Count |
| --------- | -----: |
| ERROR     |     12 |
| WARNING   |     10 |
| INFO      |      0 |
| **Total** | **22** |

### Top rules by frequency

Only seven unique rules produced findings, so the table contains all rules that generated results.

| Rule ID                                                                                             | Count | OWASP category                 |
| --------------------------------------------------------------------------------------------------- | ----: | ------------------------------ |
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`       |     6 | A03: Injection                 |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection`                              |     5 | A03: Injection                 |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` |     4 | A05: Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile`                       |     4 | A01: Broken Access Control     |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect`                     |     1 | A01: Broken Access Control     |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret`                                |     1 | A02: Cryptographic Failures    |
| `javascript.lang.security.audit.code-string-concat.code-string-concat`                              |     1 | A03: Injection                 |

### Triage shortcut

If only one rule could be fixed first, I would prioritize:

`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`

This rule produced six findings and identified SQL queries constructed from user-controlled input. Two of these findings are located in runtime application routes and correlate directly with the High severity SQL injection alerts reported by ZAP.

Fixing the shared unsafe query-construction pattern by introducing parameterized queries or prepared statements could remove several findings at once and reduce the risk of database compromise.

### Priority findings

#### Product search

Semgrep reported an SQL injection risk in:

`routes/search.ts:23`

The value from `req.query.q` is inserted directly into a raw SQL query:

```
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

The application limits the input length to 200 characters, but a length restriction does not prevent SQL injection. The query should use parameter binding or prepared statements.

#### Login

Semgrep reported an SQL injection risk in:

`routes/login.ts:34`

The value from `req.body.email` is inserted directly into the authentication query:

```
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`
)
```

Hashing the password does not protect the email field. An attacker-controlled email value can still change the structure of the SQL statement.

### False-positive sample

* File: `data/static/codefixes/unionSqlInjectionChallenge_1.ts:6`
* Rule: `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`

Semgrep correctly identifies unsafe SQL construction in this file. However, the file is located under `data/static/codefixes`, which contains educational code-fix examples for Juice Shop challenges rather than the active runtime implementation of the route.

The vulnerable code pattern is real, but this specific file is not a reachable production endpoint in the running application. It is therefore a contextual false positive when assessing the deployed application attack surface.

## Bonus Task: SAST/DAST Correlation

| ZAP finding                                  | Endpoint and parameter                     | Semgrep source location | Static cause                                                                         | Assessment                                                                                                                       |
| -------------------------------------------- | ------------------------------------------ | ----------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| SQL Injection, High severity, Low confidence | `GET /rest/products/search`, parameter `q` | `routes/search.ts:23`   | User-controlled `req.query.q` is inserted directly into a raw Sequelize SQL query    | Correlated by both tools. ZAP observed HTTP 500 after SQL-related input, while Semgrep identified the unsafe query construction. |
| SQL Injection, High severity, Low confidence | `POST /rest/user/login`, parameter `email` | `routes/login.ts:34`    | User-controlled `req.body.email` is inserted directly into a raw Sequelize SQL query | Correlated by both tools. ZAP observed HTTP 500 after a quote character, while Semgrep identified the unsafe query construction. |

### Correlation analysis

The product-search finding maps directly from the ZAP endpoint `GET /rest/products/search` to the Semgrep finding in `routes/search.ts:23`.

The login finding maps directly from the ZAP endpoint `POST /rest/user/login` to the Semgrep finding in `routes/login.ts:34`.

The correlation increases confidence because two independent analysis methods point to the same functionality:

* DAST demonstrated abnormal runtime behavior after SQL-related input.
* SAST identified direct interpolation of user-controlled data into SQL query strings.
* Manual review confirmed that the affected files are runtime application routes.

The ZAP findings still have Low confidence because an HTTP 500 response alone does not prove successful SQL injection exploitation. However, the matching Semgrep findings provide strong supporting evidence that the application constructs the queries unsafely.

## Conclusion

The authenticated scan found only 5% more alert instances than the baseline scan, so the result did not reproduce the lecture’s expected 10–20× increase.

Nevertheless, the authenticated active scan provided substantially more valuable results because it identified two High severity SQL injection findings that were absent from the baseline report.

Semgrep independently identified the corresponding unsafe SQL construction in `routes/search.ts` and `routes/login.ts`. Combining DAST, SAST, and manual review produced stronger evidence than relying on either scanner alone.
