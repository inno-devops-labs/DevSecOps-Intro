# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: <1 minutes>
- Total alerts: <10>
| Severity | Count |
|----------|------:|
| High | <0> |
| Medium | <2> |
| Low | <5> |
| Informational | <3> |

### Authenticated full scan
- Duration: <10.5 minutes>
- Total alerts: <12>
| Severity | Count |
|----------|------:|
| High | <1> |
| Medium | <4> |
| Low | <3> |
| Informational | <4> |

### The "10–20× more" claim (Lecture 5 slide 11)

- **Ratio (auth alerts / baseline alerts): 1.2×** (12 / 10)

- **Did your run match the lecture's ratio?**
  No - my ratio of 1.2× is far below the lecture's 10-20×. The comparison script counts
  unique *alert types* (deduplicated categories), not individual finding instances, and
  Juice Shop already exposes a large unauthenticated surface (the SPA shell, public REST
  endpoints, `/ftp`, `sitemap.xml`), so the baseline category count is not small to begin
  with - which compresses the ratio. The authentication effect shows up as **severity
  escalation, not raw count**: the baseline was passive-only (0 High, 2 Medium), while the
  authenticated active scan reached logic behind login and surfaced a critical **SQL Injection
  (High)** plus doubled the Medium count (1 High, 4 Medium). Measured by finding *instances*
  on the actively-scanned authenticated routes, the gap would be much closer to the lecture's
  figure.

- **Two alerts found only by the authenticated scan:**

  1. **SQL Injection** - *High*
     The injectable endpoint is a REST route that the active scan only exercised after logging
     in; the passive unauthenticated baseline never sent the crafted payloads needed to trigger
     a database error, so it could not detect the injection.

  2. **Session ID in URL Rewrite** - *Medium*
     A session identifier only exists once a user is authenticated, so the anonymous baseline
     scan had no session token to observe being leaked in the URL.

## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | **22** |

### Top rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A03 Injection |
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03 Injection |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A05 Security Misconfiguration |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01 Broken Access Control |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 Broken Access Control |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A02 Cryptographic Failures |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)
I would fix **express-sequelize-injection** first. It is the single highest-frequency rule
(6 of 22 findings), it maps to A03 Injection — the most severe class on the OWASP Top 10 — and
it is the static-analysis counterpart of the **SQL Injection (High)** that the authenticated ZAP
scan confirmed dynamically, so it is a true positive corroborated from both angles rather than a
speculative pattern. Because all six hits share the same root cause (user input concatenated into
Sequelize queries instead of being parameterised), a single module-level fix — switching to bound
parameters / the ORM's safe query API — closes the whole cluster at once.

### False-positive sample
### False-positive sample
Rule: `yaml.github-actions.security.run-shell-injection.run-shell-injection`
File: .github/workflows/update-challenges-ebook.yml:25
Reason: the rule flags the `${{ github.ref_name }}` interpolated into the `wget` URL inside the
`run:` step, but `github.ref_name` is the branch/tag name controlled by Git, not an
attacker-controllable `github.event.*` field (issue title, PR body, etc.). Tampering with it
requires push access to the repository, so an external user cannot inject shell commands here;
the rule pattern-matches any `${{ }}` in a `run:` block without distinguishing the trusted source,
making this a false positive.

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection (High) | /rest/products/search?q=%27%28 | express-sequelize-injection | routes/search.ts:23 | High (both agree) |
| 2 | A03 Injection | SQL Injection (High) | /rest/user/login (param `email`) | express-sequelize-injection | routes/login.ts:34 | High (both agree) |

### Strongest correlation deep-dive
*(Login bypass — `routes/login.ts:34`. Chosen as strongest: same High severity, but injection
into an authentication query enables full auth bypass, not just data exfiltration.)*

**1. Vulnerable code (Semgrep)** — `routes/login.ts:34`
\`\`\`js
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
\`\`\`
`req.body.email` is interpolated straight into the SQL string, so input can break out of the
quoted literal and rewrite the query's logic.

**2. Working payload (ZAP)** — `POST /rest/user/login`, param `email`
\`\`\`
email = '
\`\`\`
A single quote unbalances the string literal and produces `HTTP/1.1 500 Internal Server Error`
(SQL syntax error). The canonical exploitation of this exact line is `' OR 1=1--`, which makes
the WHERE clause always-true and logs in as the first user (admin) without a password.

**3. The fix**
Bind user input as parameters instead of concatenating it into the query text:
\`\`\`js
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  {
    replacements: { email: req.body.email || '', password: security.hash(req.body.password || '') },
    model: UserModel,
    plain: true
  }
)
\`\`\`
With bound replacements the input is escaped by the driver and treated as data, so `'` or
`' OR 1=1--` can never alter the query structure.

**4. Why both tools caught it**
Semgrep saw the static taint pattern — untrusted `req.body` flowing into a Sequelize raw query
through template-string interpolation — while ZAP confirmed it dynamically by sending `'` and
observing the 500 from the broken SQL. SAST explains *why* it's exploitable (the data path from
input to query); DAST proves *that* it's exploitable (a real error response from the running app).
A finding both tools agree on is the highest-confidence type because static reachability and
dynamic proof rarely line up by accident.

### Reflection
In a real PR review I'd want the **DAST evidence first**: a working payload that returns a SQL
error proves the bug is genuinely reachable in the running app and rules out a false positive.
The Semgrep finding then points to the exact file and line to patch — so DAST justifies the
urgency, SAST pinpoints the fix.
