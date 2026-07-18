# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: around 2 minutes
- Total alerts: 10 unique alert types
- Total instances: 41
High - 0
Medium - 2
Low - 5
Informational - 3

### Authenticated full scan
- Duration: around 6 minutes (spider: 18s, ajax spider: 49s, active scan: 4m 52s)
- Total alerts: 12 unique alert types
- Total instances: 37
High - 1 (SQL Injection)
Medium - 4
Low - 3
Informational - 4

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 1.2× (12/10 alert types)
- Did your run match the lecture's ratio? No, this is significantly lower than the claimed 10-20×. This occurred because Juice Shop is intentionally vulnerable on its public surface, so the baseline scan already found many configuration issues. Additionally, ZAP's active scanning was conservative, marking the SQL injection as "High (Low)" confidence. In a real production application with proper public-surface hardening, the authenticated scan would reveal a much larger ratio of hidden vulnerabilities behind the login wall.

### Two auth-only alerts
1. SQL Injection (High)
   - Endpoint: `/rest/products/search?q=%27%28`
   - Why unreachable to baseline: The product search functionality with SQL injection requires constructing specific query parameters. While the endpoint is technically public, the active scanning that discovered the injection only ran during the authenticated scan with proper session context and dedicated attack time.

2. Private IP Disclosure (Low)
   - Endpoint: `/rest/admin/application-configuration`
   - Why unreachable to baseline: This admin-only endpoint requires authentication. The baseline scanner cannot access `/rest/admin/*` routes without a valid session token, making this finding invisible to unauthenticated scanning.


---

## Task 2: SAST with Semgrep

### Semgrep severity breakdown
- ERROR: 12
- WARNING: 10
- Total: 22

### Top 7 rules by frequency
1. javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection — 6 findings — A03 Injection
2. yaml.github-actions.security.run-shell-injection.run-shell-injection — 5 findings — A03 Injection (CI/CD)
3. javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing — 4 findings — A05 Security Misconfiguration
4. javascript.express.security.audit.express-res-sendfile.express-res-sendfile — 4 findings — A01 Broken Access Control
5. javascript.express.security.audit.express-open-redirect.express-open-redirect — 1 finding — A01 Broken Access Control
6. javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret — 1 finding — A02 Cryptographic Failures
7. javascript.lang.security.audit.code-string-concat.code-string-concat — 1 finding — A03 Injection

### Triage shortcut (Lecture 5 slide 8)
If I could fix only one rule, I would fix sequelize-injection-express (6 findings). This is the highest-frequency rule and represents actual SQL injection vulnerabilities in production route handlers (routes/search.ts, routes/login.ts), not just codefix examples. Fixing this one pattern with parameterized queries across all Sequelize calls would close 6 critical injection points, including the one confirmed by DAST (correlated finding below). The GitHub Actions shell injection findings (5 occurrences) are in CI/CD workflows with lower exploitability than runtime SQL injection that directly exposes the database.

### False-positive sample
Finding: data/static/codefixes/dbSchemaChallenge_1.ts:5 — express-sequelize-injection
Reason: This file is an intentionally vulnerable code snippet used for Juice Shop's own security training challenges. The code is never executed in production — it's static educational content displayed to users learning about SQL injection. The Sequelize query in this file is deliberately crafted to be vulnerable for teaching purposes and is not part of the running application's route handlers.

---

## Bonus: SAST/DAST Correlation

### Correlation findings
1. A03 Injection — ZAP: SQL Injection at /rest/products/search?q='( — Semgrep: express-sequelize-injection at routes/search.ts:23 — Confidence: High (both agree)
2. A03 Injection — ZAP: SQL Injection at /rest/user/login (POST) — Semgrep: express-sequelize-injection at routes/login.ts:34 — Confidence: High (both agree)

### Strongest correlation deep-dive

Vulnerable code (routes/search.ts:23):
export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
      .then(([products]: any) => {
        const dataString = JSON.stringify(products)
        // ... challenge checking logic ...
        res.json(utils.queryResultToJson(products))
      })
  }
}

Working payload (from ZAP report):
GET /rest/products/search?q='(

The attack payload '( is URL-encoded as %27%28. This causes a SQL syntax error resulting in HTTP 500 Internal Server Error, confirming the parameter is injectable. A real attacker could escalate to:
- ' OR '1'='1' -- to dump all products
- ' UNION SELECT email, password FROM Users -- to extract user credentials

The fix — parameterized query with Sequelize:
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`,
  {
    replacements: { criteria: `%${criteria}%` },
    type: models.sequelize.QueryTypes.SELECT
  }
)

Or even better, using Sequelize model finders (safe by default):
Product.findAll({
  where: {
    [Op.or]: [
      { name: { [Op.like]: `%${criteria}%` } },
      { description: { [Op.like]: `%${criteria}%` } }
    ],
    deletedAt: null
  },
  order: [['name', 'ASC']]
})

### Why both tools caught it
This vulnerability was discoverable from both angles because it exhibits the classic SQL injection pattern: user input flows directly into a SQL query via string concatenation. Semgrep's static analysis detected the tainted data flow (req.query.q → template literal ${criteria} → sequelize.query()) without needing to execute the code. ZAP's dynamic analysis confirmed exploitability by sending actual SQL metacharacters ('() and observing the database error response (500 status code). The same fundamental weakness — building SQL queries through string interpolation instead of parameterized queries — is visible both in the source code (SAST) and in the runtime behavior (DAST).

### Reflection
Lecture 5 slide 15 calls this "the highest-confidence finding type" because SAST and DAST provide complementary evidence that eliminates false positives from either tool alone. In a real PR review, I would want the SAST finding first because it pinpoints the exact line of code that needs fixing (line 23 in routes/search.ts), enabling immediate remediation. The DAST evidence then serves as proof that the fix is necessary and provides the exact payload to test against the patched code. Together, they create an irrefutable case: the code pattern is provably dangerous AND the running application is provably exploitable.

