# Lab 5 - Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- Duration: 1.5 minutes (`real 89.86s`)
- Total alerts: 10 alert types

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan

- Duration: 11.2 minutes (`real 669.00s`)
- Total alerts: 12 alert types
- Note: the original parallel active scan was OOM-killed locally, so the successful authenticated run kept the original scan durations (`spider: 5`, `spiderAjax: 10`, `activeScan: 10`) and ran active scanning with `threadPerHost: 1`. The scan completed spider, AJAX spider, passive scan, the full 10-minute active-scan cap, and generated `auth-report.json`.

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10-20x more" claim (Lecture 5 slide 11)

- Ratio by ZAP alert type count: `12 / 10 = 1.2x`
- My run did not match the lecture's 10-20x ratio when counted by ZAP alert types. The authenticated AJAX spider did expand coverage substantially (`993` URLs discovered vs `158` in baseline output), but ZAP's JSON groups repeated evidence into alert types rather than counting every reached route or instance as a separate issue.

Two specific alerts only found by the authenticated scan:

| Alert | Severity | Evidence | Why baseline missed it |
|-------|----------|----------|-------------------------|
| SQL Injection | High | `GET /rest/products/search?q=%27%28`, parameter `q`, attack payload `"'("`, evidence `HTTP/1.1 500 Internal Server Error` | The baseline scan is passive/unauthenticated, while the authenticated full scan actively fuzzed application parameters. |
| Private IP Disclosure | Low | `GET /rest/admin/application-configuration`, evidence `192.168.99.100:3000` | This is an admin application-configuration endpoint discovered after authenticated crawling, not part of the unauthenticated baseline surface. |

## Task 2: SAST with Semgrep

Source scanned: OWASP Juice Shop `v20.0.0`, commit `f356a09`, matching the running Docker image tag.

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
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01 Broken Access Control |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)

I would fix `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` first. It is the most frequent rule, it has `ERROR` severity, and two findings are in live Express routes (`routes/search.ts` and `routes/login.ts`) that ZAP also exercised dynamically. Fixing the query-building pattern at the route/model boundary would remove multiple high-impact injection paths instead of only cleaning up isolated findings.

### False-positive sample

I would suppress `/src/data/static/codefixes/unionSqlInjectionChallenge_3.ts:10` for this deployment triage. The code is intentionally vulnerable training/static codefix material under `data/static/codefixes`, not the live route implementation serving the running app, so it is useful educational content but not a deployed runtime finding.

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/search.ts:23` | High: DAST payload reaches the same SQL string interpolation Semgrep flagged |
| 2 | A03 Injection | SQL Injection | `/rest/user/login` (`email` parameter) | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/login.ts:34` | High: ZAP triggered SQL error behavior on the same tainted Sequelize query |

### Strongest correlation deep-dive

Strongest finding: SQL Injection in product search.

Vulnerable code from `routes/search.ts:21-23`:

```ts
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

Working payload from ZAP:

```text
GET /rest/products/search?q=%27%28
Parameter: q
Attack: '(
Evidence: HTTP/1.1 500 Internal Server Error
```

Proposed fix:

```ts
const criteria = String(req.query.q === 'undefined' ? '' : req.query.q ?? '').slice(0, 200)

models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
  {
    replacements: { criteria: `%${criteria}%` }
  }
)
```

Why both tools caught it: Semgrep saw untrusted Express request data flow into a raw Sequelize SQL string, and ZAP confirmed that changing `q` at runtime produced SQL-error behavior. This is the high-confidence static-plus-dynamic overlap from Lecture 5 slide 15.

### Reflection

In a real PR review, I would want the DAST evidence first for prioritization because it proves exploitability against the running application and gives a concrete payload. Then I would use the SAST finding to make the fix fast and complete, because it points directly to the vulnerable source line and reveals the same pattern in related routes like login.
