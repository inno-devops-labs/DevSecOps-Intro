# Lab 5 - Submission



## Task 1: DAST with OWASP ZAP



### Baseline (unauthenticated) scan



- Duration: approximately 1-3 minutes

- Total alert instances: 41

- Total alert types: 10



| Severity | Count |

|----------|------:|

| High | 0 |

| Medium | 9 |

| Low | 21 |

| Informational | 11 |

| \*\*Total\*\* | \*\*41\*\* |



### Authenticated full scan



- Duration: approximately 5-10 minutes

- Total alert instances: 37

- Total alert types: 12



| Severity | Count |

|----------|------:|

| High | 2 |

| Medium | 16 |

| Low | 9 |

| Informational | 10 |

| \*\*Total\*\* | \*\*37\*\* |



### The "10-20x more" claim



- Baseline instances: 41

- Authenticated instances: 37

- Ratio: 37 / 41 = 0.90x



My run did not match the lecture's expected 10-20x increase for authenticated DAST. The authenticated scan found several additional categories that were not present in the baseline scan, including SQL Injection and session-management findings, but the total number of alert instances was slightly lower. This likely happened because the authenticated scan configuration, crawling coverage, and report filtering differed from the baseline scan.



### Two alerts found only by the authenticated scan



#### 1. SQL Injection



- Alert title: SQL Injection

- Severity: High

- Count: 2



This alert was unreachable to the unauthenticated baseline scan because the vulnerable functionality was discovered during the authenticated scan after ZAP logged in as the admin user. The baseline scan did not authenticate, so it had less access to protected application routes and user-specific behavior.



#### 2. Session ID in URL Rewrite



- Alert title: Session ID in URL Rewrite

- Severity: Medium

- Count: 5



This alert was unreachable to the unauthenticated baseline scan because a real authenticated session had to be created before ZAP could observe session identifiers being handled in URLs. The baseline scan did not establish an authenticated user session.



### Auth-only findings observed



| Alert | Severity | Count |

|-------|----------|------:|

| SQL Injection | High | 2 |

| Missing Anti-clickjacking Header | Medium | 1 |

| Session ID in URL Rewrite | Medium | 5 |

| Private IP Disclosure | Low | 1 |

| X-Content-Type-Options Header Missing | Low | 3 |

| Authentication Request Identified | Informational | 1 |

| Session Management Response Identified | Informational | 1 |

| User Agent Fuzzer | Informational | 3 |



## Task 2: SAST with Semgrep



### Semgrep severity breakdown



| Severity | Count |

|----------|------:|

| ERROR | 12 |

| WARNING | 10 |

| INFO | 0 |

| \*\*Total\*\* | \*\*22\*\* |



### Top rules by frequency



| Rule ID | Count | OWASP category |

|---------|------:|----------------|

| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A03 Injection |

| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03 Injection |

| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A05 Security Misconfiguration |

| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01 Broken Access Control |

| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A07 Identification and Authentication Failures |

| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03 Injection |

| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 Broken Access Control |



### Triage shortcut



If I had time to fix only one rule first, I would start with `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`. It appears 6 times and maps directly to OWASP A03 Injection, which is usually high impact because user-controlled input can reach database queries. Fixing the query construction pattern at the module level would likely remove several findings at once.



### False-positive sample



One finding I would suppress after review is:



- Rule: `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`

- File: `labs/lab5/semgrep/juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts`

- Line: 5



Reason: this file is inside `data/static/codefixes/`, which appears to contain educational challenge fix snippets rather than the live application route handling production traffic. The pattern is useful as training material, but it is not necessarily exploitable as a runtime vulnerability in the deployed app.

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP category | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|----------------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/search.ts:23` | High - both tools identified SQL injection on the product search functionality |

### Strongest correlation deep-dive

The strongest correlated finding is SQL Injection in the product search functionality.

#### Vulnerable code

File: `labs/lab5/semgrep/juice-shop/routes/search.ts`

```ts
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

The vulnerability is caused by direct string interpolation of `criteria` into a SQL query. The value comes from `req.query.q`, which is controlled by the user.

#### Working payload from ZAP

ZAP reported the following dynamic evidence:

```text
URI: http://juice-shop:3000/rest/products/search?q=%27%28
Method: GET
Parameter: q
Attack: '(
Evidence: HTTP/1.1 500 Internal Server Error
```

This indicates that malformed SQL input caused a server-side error, which is consistent with SQL injection behavior.

#### Proposed remediation

The query should be rewritten to use parameterized queries or Sequelize query replacements instead of string interpolation.

Example safer approach:

```ts
const criteria = typeof req.query.q === 'string' ? req.query.q.substring(0, 200) : ''

models.sequelize.query(
  `SELECT * FROM Products
   WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL)
   ORDER BY name`,
  {
    replacements: { search: `%${criteria}%` }
  }
)
```

This keeps user input as a bound parameter instead of concatenating it into the SQL string.

#### Why both tools caught it

Semgrep caught the issue statically because it detected user-controlled input from `req.query.q` flowing into `models.sequelize.query()` through string interpolation. ZAP caught it dynamically because sending a SQL-breaking payload to the `/rest/products/search` endpoint triggered a `500 Internal Server Error`.

### Reflection

In a real PR review, I would want the SAST finding first because it points directly to the vulnerable source file and line that need to be fixed. However, the DAST evidence is important because it proves the issue is reachable and exploitable through a real HTTP endpoint. Together, they provide much higher confidence than either result alone.

