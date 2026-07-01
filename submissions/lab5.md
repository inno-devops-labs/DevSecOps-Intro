# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: 1 minute 13 seconds
- Total alert instances: 18

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 8 |
| Low | 5 |
| Informational | 5 |

Baseline alerts:
- Content Security Policy (CSP) Header Not Set — Medium, 5 instances
- Cross-Domain Misconfiguration — Medium, 3 instances
- Timestamp Disclosure - Unix — Low, 5 instances
- Modern Web Application — Informational, 5 instances

### Authenticated scan
- Duration: 31 seconds
- Total alert instances: 22

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 10 |
| Low | 5 |
| Informational | 7 |

Authenticated alerts:
- Content Security Policy (CSP) Header Not Set — Medium, 5 instances
- Cross-Domain Misconfiguration — Medium, 5 instances
- Timestamp Disclosure - Unix — Low, 5 instances
- Authentication Request Identified — Informational, 1 instance
- Modern Web Application — Informational, 5 instances
- Session Management Response Identified — Informational, 1 instance

### The "10–20× more" claim

- Ratio: 22 / 18 = 1.22x
- My run did not match the 10–20x claim. The provided full authenticated active scan repeatedly failed during the `activeScan` job in Docker Desktop before generating reports, so I used an authenticated spider/passive scan to preserve authenticated coverage and produce a report. This still showed authentication-specific findings, but it did not exercise the full active DAST depth expected by the lecture example.

Two alerts only visible in the authenticated report:

1. Authentication Request Identified — Informational
   - This appeared only after ZAP submitted the Juice Shop login request as the configured admin user.
2. Session Management Response Identified — Informational
   - This required authenticated traffic because ZAP had to observe login/session handling responses.

## Task 2: SAST with Semgrep

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

I would fix `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` first. It is the most frequent rule, has ERROR severity, and includes reachable application routes such as `routes/search.ts` and `routes/login.ts`. Fixing the query construction pattern at the module level would remove several high-impact injection findings at once.

### False-positive sample

I would suppress `yaml.github-actions.security.run-shell-injection.run-shell-injection` in `.github/workflows/update-challenges-ebook.yml:22` after review. The finding is valid as a general CI hardening warning, but in this repository it scans project workflow metadata rather than the running Juice Shop web application, so it is not relevant to the deployed target assessed in this lab.

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP / DAST evidence | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|---------------------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | Manual DAST request against the Juice Shop search endpoint returned a SQL error for a UNION payload | `/rest/products/search?q=')) UNION SELECT * FROM Users--` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/search.ts:23` | High: SAST shows tainted query construction and DAST confirms database error behavior on the mapped endpoint |

### Strongest correlation deep-dive

Semgrep finding:

```ts
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

Working DAST payload:

```text
/rest/products/search?q=%27))%20UNION%20SELECT%20*%20FROM%20Users--
```

Observed result:

```text
SQLITE_ERROR: SELECTs to the left and right of UNION do not have the same number of result columns
```

The fix is to replace string interpolation with parameterized query binding. For example:

```ts
const criteria = String(req.query.q === 'undefined' ? '' : req.query.q ?? '').substring(0, 200)

models.sequelize.query(
  `SELECT * FROM Products
   WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL)
   ORDER BY name`,
  {
    replacements: { search: `%${criteria}%` }
  }
)
```

Both tools caught this because the vulnerable route directly copies user-controlled `req.query.q` into a SQL string. Semgrep detected the tainted source-to-sink flow statically, while DAST confirmed that an injected payload changes backend SQL execution behavior.

### Reflection

In a real PR review I would want the SAST finding first because it points directly to the vulnerable file and line, which makes remediation faster. I would still attach the DAST evidence because it proves exploitability against the running application and raises confidence that this is not just a theoretical code pattern.
