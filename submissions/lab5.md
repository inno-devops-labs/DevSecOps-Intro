# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- Duration: ~1 minute
- Total alerts: 10

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan

- Duration: 385 seconds (~6.4 minutes)
- Total alerts: 12

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

The authenticated scan was completed successfully with the provided ZAP Automation Framework configuration. The scan used the admin user, the normal spider, Ajax spider, passive scan wait, active scan, and generated both auth-report.html and auth-report.json.

### The "10–20× more" claim

- Ratio: 12 / 10 = 1.2×

My run did not match the lecture's 10–20× claim. The authenticated scan did find more alerts than the unauthenticated baseline, but not by an order of magnitude. However, the authenticated scan reached deeper application behavior and found a High severity SQL Injection issue that was absent from the unauthenticated baseline scan, so the authenticated scan still provided higher-value findings.

### Two authenticated-only alerts

1. **SQL Injection** — High  
   This was not found by the unauthenticated baseline scan because the authenticated scan crawled and actively tested deeper application routes, including /rest/products/search, where malformed input caused a server-side SQL error.

2. **Session ID in URL Rewrite** — Medium  
   This was not found by the unauthenticated baseline scan because session-related behavior only appears after ZAP logs in and observes authenticated traffic.

Additional authenticated-only examples included Authentication Request Identified, Session Management Response Identified, Missing Anti-clickjacking Header, Private IP Disclosure, User Agent Fuzzer, and X-Content-Type-Options Header Missing.

---

## Task 2: SAST with Semgrep

Semgrep CE 1.168.0 was run against the pinned OWASP Juice Shop v20.0.0 source code. This matches the Docker image used for the DAST scan: bkimminich/juice-shop:v20.0.0.

### Semgrep severity breakdown

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | 22 |

### Top 10 rules by frequency

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A03 Injection |
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03 Injection |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A05 Security Misconfiguration |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01 Broken Access Control |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 Broken Access Control |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A02 Cryptographic Failures |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03 Injection |

### Triage shortcut

I would fix javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection first. It appears 6 times, maps to OWASP A03 Injection, and includes findings where user-controlled input reaches raw SQL queries. Fixing this pattern with parameterized queries would remove several related findings and reduce the risk of real database compromise.

### False-positive sample

One finding I would suppress as a false positive after review is javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection in data/static/codefixes/dbSchemaChallenge_1.ts. This file is a static educational code-fix snippet for a Juice Shop challenge, not the actual runtime route that handled the ZAP request, so it should not be treated with the same priority as routes/search.ts.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | /rest/products/search?q=%27%28 | javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | routes/search.ts:23 | High — both tools found the same SQL injection path |

### Strongest correlation deep-dive

#### Vulnerable code

    // vuln-code-snippet start unionSqlInjectionChallenge dbSchemaChallenge
    export function searchProducts () {
      return (req: Request, res: Response, next: NextFunction) => {
        let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
        criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
        models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
          .then(([products]: any) => {

#### Working payload from ZAP

    '(

ZAP sent the payload to:

    http://juice-shop:3000/rest/products/search?q=%27%28

and observed:

    HTTP/1.1 500 Internal Server Error

#### Proposed fix

The vulnerable code directly embeds the user-controlled criteria value into a SQL string. The fix is to use parameterized queries or Sequelize replacements instead of string interpolation. For example, the search term should be passed as a bound parameter and reused safely in the LIKE expressions, rather than being inserted into the query with ${criteria}.

Example remediation approach:

    const criteria = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    const limitedCriteria = String(criteria).length <= 200 ? String(criteria) : String(criteria).substring(0, 200)

    models.sequelize.query(
      `SELECT * FROM Products
       WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL)
       ORDER BY name`,
      {
        replacements: { search: `%${limitedCriteria}%` }
      }
    )

#### Why both tools caught it

Semgrep caught the issue statically because it saw request-controlled data from req.query.q flowing into models.sequelize.query. ZAP caught it dynamically because sending a malformed SQL payload to /rest/products/search triggered a server-side SQL error response.

### Reflection

Lecture 5 slide 15 calls this the highest-confidence finding type because both static and dynamic evidence point to the same issue. In a real PR review, I would want the DAST evidence first because it proves the vulnerability is reachable and observable at runtime. Then I would use the SAST finding to locate the vulnerable source line and implement the fix.
