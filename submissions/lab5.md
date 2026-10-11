# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: 3 minutes 35 seconds
- Total alerts: 10

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: 16 minutes 09 seconds
- Total alerts: 12

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)

- Ratio (auth alerts / baseline alerts): 1.20× (12 / 10)

My run did not match the lecture's 10–20× ratio. The baseline scan already crawled many public Juice Shop routes, while the authenticated scan produced only two additional alert types. The comparison also combines two different scan modes: the baseline scan was passive, whereas the authenticated scan used AJAX crawling and active attack payloads. In addition, the comparison counts alert types rather than every individual finding instance.

Two alerts found only by the authenticated full scan:

1. **SQL Injection — High**
   - ZAP URI: `/rest/products/search?q=%27%28`
   - Evidence: `HTTP/1.1 500 Internal Server Error`
   - The search endpoint itself was publicly reachable (`HTTP 200` for a normal unauthenticated request), but the baseline scan was passive and did not inject malicious SQL payloads. The full scan actively tested the parameter and triggered the error response.

2. **Session ID in URL Rewrite — Medium**
   - ZAP URI: `/socket.io/?EIO=4&transport=polling&t=PxdJcYL&sid=H-FC1OKYahGpm5dWAAGw`
   - Evidence: `H-FC1OKYahGpm5dWAAGw`
   - The baseline crawl did not create and follow the interactive Socket.IO polling session that generated the dynamic `sid` parameter. The AJAX-enabled authenticated scan established this session and exposed the session identifier in the URL.

## Task 2: SAST with Semgrep

Semgrep CE version: 1.167.0.

The scan was executed against the source code pinned to the `v20.0.0` tag, matching the `bkimminich/juice-shop:v20.0.0` container used for DAST.

### Semgrep severity breakdown

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | **22** |

### Top 10 rules by frequency

Only seven distinct rule IDs remained after filtering to ERROR and WARNING findings.

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03:2021 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03:2021 Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A01:2021 Broken Access Control |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A04:2021 Insecure Design |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01:2021 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A07:2021 Identification and Authentication Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03:2021 Injection |

### Triage shortcut

I would fix `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` first. It appears six times and represents SQL queries built from request-controlled values, which can lead to data disclosure or authentication bypass. It also affects a runtime route, `routes/search.ts`, where the finding was independently confirmed by ZAP.

### False-positive sample

`data/static/codefixes/dbSchemaChallenge_1.ts:5` was flagged by `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`. The SQL concatenation is intentionally present in a static code-fix example under `data/static/codefixes/`. A repository-wide search found no runtime import of this file; it is not an executable application route or module, so I would suppress this occurrence with a documented reason rather than treat it as a production runtime finding.

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP category | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|----------------|-----------|---------|--------------|-------------------|------------|
| 1 | A03:2021 Injection | SQL Injection — High | `/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/search.ts:23` | High — both tools agree |

### Strongest correlation deep-dive

**Semgrep evidence**

```ts
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)

models.sequelize.query(
  `SELECT * FROM Products
   WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%')
   AND deletedAt IS NULL)
   ORDER BY name`
)
```

The `q` query parameter is inserted directly into the SQL statement through a template literal.

**ZAP evidence**

- URI: `/rest/products/search?q=%27%28`
- Method: `GET`
- Parameter: `q`
- Payload: `'(`
- Evidence: `HTTP/1.1 500 Internal Server Error`

**Proposed remediation**

Use a parameterized query instead of SQL string interpolation:

```ts
models.sequelize.query(
  `SELECT * FROM Products
   WHERE ((name LIKE :criteria OR description LIKE :criteria)
   AND deletedAt IS NULL)
   ORDER BY name`,
  {
    replacements: { criteria: `%${criteria}%` }
  }
)
```

Semgrep detected unsafe data flow from `req.query.q` to `sequelize.query()`. ZAP dynamically supplied a malformed SQL payload to the same endpoint and observed a server error, confirming that the issue is reachable in the running application.

### Reflection

For a real PR review, I would first use the DAST evidence to prioritize the issue because it demonstrates that the endpoint is reachable and the payload has a real runtime effect. I would then use the SAST finding to locate the vulnerable code precisely and implement the correct fix. Together, the two reports provide stronger evidence than either scanner alone.
