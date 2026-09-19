# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~2 minutes
- Total alerts: 10

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: ~5 minutes
- Total alerts: 12

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 1.2x
- This run did not match the lecture's 10-20x rule of thumb. The authenticated scan still found additional alert types and the only High-severity finding, but the baseline scan had already covered a broad public surface, so the delta was small in this environment.
- Two specific alerts found only by the authenticated scan:
  1. `SQL Injection` — High  
     This appeared on `/rest/products/search` and `/rest/user/login`, and the unauthenticated baseline run did not actively exercise these flows with the same attack payloads.
  2. `Session Management Response Identified` — Informational  
     This depended on observing post-login traffic such as `/rest/user/login` returning `authentication.token`, which the unauthenticated baseline scan never produced.

## Task 2: SAST with Semgrep

Pinned source version scanned:
- Juice Shop tag: `v20.0.0`
- Checked out commit: `f356a0920`

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
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03:2021 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03:2021 Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05:2021 Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A05:2021 Security Misconfiguration |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01:2021 Broken Access Control / redirect abuse |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02:2021 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03:2021 Injection |

Only 7 unique rules fired in this run, so the table includes all of them.

### Triage shortcut (Lecture 5 slide 8)
If I had time to fix only one rule first, I would choose `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`. It is the most important application-code finding because it appears multiple times in live request handlers such as `routes/search.ts` and `routes/login.ts`, and ZAP independently confirmed SQL injection dynamically, which raises confidence and remediation priority.

### False-positive sample
I would suppress `yaml.github-actions.security.run-shell-injection.run-shell-injection` at `labs/lab5/semgrep/juice-shop/.github/workflows/update-challenges-ebook.yml:22` after review. The flagged value uses `${{ github.ref_name }}`, but this workflow is restricted to repository-controlled triggers on `master` and `develop`, so this is not representative of user-controlled runtime input in the deployed application.

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/search.ts:23` | High |
| 2 | A03 Injection | SQL Injection | `/rest/user/login` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/login.ts:34` | High |

### Strongest correlation deep-dive

Vulnerable code from `routes/search.ts:23`:

```ts
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

Working payload from ZAP:
- Endpoint: `/rest/products/search`
- Parameter: `q`
- Attack: `'(`
- Full URI seen in report: `http://juice-shop:3000/rest/products/search?q=%27%28`
- Evidence: `HTTP/1.1 500 Internal Server Error`

Proposed fix:
- Replace raw string interpolation with a parameterized query using Sequelize replacements or bind parameters.
- Keep the wildcard logic in the bound value instead of concatenating untrusted input into SQL syntax.

Example fix direction:

```ts
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
  { replacements: { criteria: `%${criteria}%` } }
)
```

Why both tools caught it:
- Semgrep identified a classic tainted-data flow from `req.query.q` into a raw SQL query string.
- ZAP confirmed the same weakness dynamically by sending a crafted payload to the live endpoint and triggering a server error consistent with SQL injection handling.

### Reflection (2-3 sentences)
Lecture 5 slide 15 calls this the highest-confidence finding type, and this lab showed why. In a real PR review I would want the DAST evidence first because it proves the issue is reachable and exploitable in the running app, then I would use the SAST result to jump directly to the vulnerable line and implement the fix faster.
