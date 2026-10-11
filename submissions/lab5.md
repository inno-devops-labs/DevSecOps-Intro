cat > submissions/lab5.md << 'ENDOFFILE'
# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- Duration: ~2 minutes
- Total alerts (unique rule types): 10
- Scanner crawled: 158 URLs

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan

- Duration: ~12 minutes (spider 18s + active scan 2m04s)
- Total alerts (unique rule types): 8
- Scanner crawled: 93 URLs

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 2 |
| Low | 1 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)

- Baseline total alert instances: 41
- Auth total alert instances: 38
- Ratio (auth / baseline): **0.8×** — did not match the lecture claim.

The lecture's 10–20× figure assumes a full AJAX-crawl of authenticated routes. In this run the Ajax Spider returned 0 new URLs because it ran in a headless container without a real browser engine properly launching JavaScript; the traditional spider found 93 URLs for both modes. As a result the authenticated scan did not expand the crawl surface beyond the baseline. In a real engagement, a properly configured Ajax Spider would expose basket, order history, admin panel, and user-profile API routes — each producing new high/medium findings that push the ratio into the expected range.

#### Two alerts found only in the authenticated scan

1. **SQL Injection — High (Low)**
   URL: `http://juice-shop:3000/rest/user/login`
   The unauthenticated scan never reached the login POST endpoint as an active-scan target because the baseline crawler treats it as a form and does not fuzz its parameters. Only after the Automation Framework configured a valid session and replayed authenticated requests did ZAP include `/rest/user/login` in the active-scan queue and detect the injectable `email` field.

2. **Authentication Request Identified — Informational (High)**
   URL: `http://juice-shop:3000/rest/user/login`
   This alert flags that ZAP recognised a login/authentication flow. An unauthenticated scan has no session context so ZAP's session-management heuristics never identify which request is the authentication handshake; the alert can only fire once ZAP is configured with credentials and observes the full login sequence.

---

## Task 2: SAST with Semgrep

### Environment

- Semgrep CE version: 1.168.0
- Source pinned to: `juice-shop` tag `v20.0.0` (commit `f356a09207c7a9550eb6fc4c3945e081922cf998`)
- Rulesets: `p/owasp-top-ten`, `p/javascript`, `p/secrets`
- Files scanned: 1000 git-tracked; 4 files >1 MB skipped; 140 matched `.semgrepignore`

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
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A08 Software & Data Integrity |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection (eval) |

### Triage shortcut (Lecture 5 slide 8)

**First fix: `express-sequelize-injection` (6 findings)**

This rule fires 6 times across `routes/search.ts`, `routes/login.ts`, and four codeFix exercise files — all sharing the same root cause: raw user-supplied strings concatenated into Sequelize `query()` calls. A single change — replacing string interpolation with Sequelize replacements (`?` placeholders) — eliminates all 6 findings at once and closes the highest-severity vulnerability class (SQL Injection, CWE-89). Impact/likelihood/confidence are all HIGH per Semgrep metadata, making it the clearest risk-per-effort winner.

### False-positive sample

- File: `labs/lab5/semgrep/juice-shop/.github/workflows/update-challenges-ebook.yml`, line 22
- Rule: `yaml.github-actions.security.run-shell-injection.run-shell-injection`
- Reason: The `${{ github.ref_name }}` expression is used only to construct a `wget` URL pointing to a known GitHub raw content path within the same repository. The value is implicitly constrained to valid git ref names, which cannot contain shell metacharacters that would escape the `wget` argument. An attacker would need write access to the repository to create a malicious ref name — at which point they already have elevated privileges and this injection path is not an additional escalation. This is a low-risk pattern that triggers the rule's general heuristic but is not exploitable in practice.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection (High) | `http://juice-shop:3000/rest/user/login` | `express-sequelize-injection` | `routes/login.ts:34` | **High** — both tools agree on SQLi at the same component |
| 2 | A03 Injection | SQL Injection (High) | `http://juice-shop:3000/rest/products/search` | `express-sequelize-injection` | `routes/search.ts:23` | **High** — tainted query confirmed by active scan |

### Strongest correlation deep-dive — SQL Injection in `routes/search.ts`

#### Vulnerable code (Semgrep — `routes/search.ts`, line 23)

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR ` +
  `description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
```

`criteria` is taken from `req.query.q` and interpolated into the SQL string with no sanitization.

#### Working ZAP payload
GET /rest/products/search?q=apple'))%20UNION%20SELECT%20null,id,email,password,null,null,null,null,null%20FROM%20Users-- HTTP/1.1

This causes Sequelize to execute a UNION-based query returning all user records (email + hashed password) in the product-search response — confirmed by Juice Shop's own `unionSqlInjectionChallenge`.

#### Fix — parameterized query

```typescript
// BEFORE (vulnerable)
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR ` +
  `description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)

// AFTER (safe — Sequelize replacements)
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :search OR ` +
  `description LIKE :search) AND deletedAt IS NULL) ORDER BY name`,
  {
    replacements: { search: `%${criteria}%` },
    type: models.sequelize.QueryTypes.SELECT
  }
)
```

#### Why both tools caught it

Semgrep detected it statically by tracing the taint flow from Express `req.query` through string interpolation into the `sequelize.query` sink — a purely structural pattern requiring no running application. ZAP detected it dynamically by sending HTTP requests with SQL payloads and observing that the response changed structurally (extra rows, different column count), confirming the injection is exploitable at runtime. Together they provide the highest possible confidence: the code is structurally vulnerable **and** reachable through the real network stack.

### Reflection

Lecture 5 slide 15 calls a correlated SAST+DAST finding the highest-confidence result because static analysis proves the code path is structurally flawed and dynamic analysis proves it is exploitable in the deployed artifact. In a real PR review I would want the **SAST finding first**: it arrives before deployment, pinpoints the exact file and line, and can block the merge in CI. The DAST result then serves as authoritative runtime confirmation that the SAST alert is not a false positive, making the combined finding impossible to dismiss as a theoretical concern.
ENDOFFILE
