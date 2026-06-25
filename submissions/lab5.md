# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Total alerts: **9**

| Severity      | Count |
|---------------|------:|
| High          |     0 |
| Medium        |     2 |
| Low           |     5 |
| Informational |     2 |

Alerts found:
- Content Security Policy (CSP) Header Not Set (Medium)
- Cross-Domain Misconfiguration (Medium)
- Cross-Origin-Embedder-Policy Header Missing (Low)
- Cross-Origin-Opener-Policy Header Missing (Low)
- Dangerous JS Functions (Low)
- Deprecated Feature Policy Header Set (Low)
- Timestamp Disclosure - Unix (Low)
- Modern Web Application (Info)
- Storable but Non-Cacheable Content (Info)

### Authenticated full scan
- Total alerts: **12**

| Severity      | Count |
|---------------|------:|
| High          |     1 |
| Medium        |     4 |
| Low           |     3 |
| Informational |     4 |

Alerts found (new vs baseline highlighted):
- **SQL Injection (High)** ← auth-only
- Content Security Policy (CSP) Header Not Set (Medium)
- **Session ID in URL Rewrite (Medium)** ← auth-only
- Cross-Domain Misconfiguration (Medium)
- **Missing Anti-clickjacking Header (Medium)** ← auth-only
- Timestamp Disclosure - Unix (Low)
- **Private IP Disclosure (Low)** ← auth-only
- X-Content-Type-Options Header Missing (Low)
- Authentication Request Identified (Info)
- Modern Web Application (Info)
- Session Management Response Identified (Info)
- User Agent Fuzzer (Info)

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): **12 / 9 = 1.33×**
- The run did **not** match the lecture's claimed 10–20× ratio. The gap here is much smaller because ZAP's active scan was time-limited to 10 minutes (`maxScanDurationInMins: 10`) and the Juice Shop surface is Angular SPA — much of the app only renders after JavaScript execution, so the traditional spider missed large portions of the route tree that a longer Ajax-spider run would have covered. The ratio would grow significantly with a longer crawl budget and a properly seeded context (e.g., recording a manual login + navigation session as a seed for the Ajax spider).
- The qualitative difference is still clear: the single most critical finding — **SQL Injection (High)** — was found exclusively by the authenticated scan. Zero High findings in baseline, 1 High in auth. That one finding alone justifies the auth setup.

**Two auth-only alerts:**

1. **SQL Injection (High)** at `/rest/products/search?q=` and `/rest/user/login`
   — The search and login endpoints require the active scanner to issue requests that look like real user interactions; the baseline passive-only spider never sent a crafted `q=` parameter with SQL metacharacters because it never received a token to probe authenticated routes.

2. **Session ID in URL Rewrite (Medium)** at multiple authenticated endpoints
   — Session tokens appear in URLs only after a successful login flow. Without authentication the scanner never received a JWT in the response, so it had no session value to observe being rewritten into link hrefs.

---

## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity  | Count |
|-----------|------:|
| ERROR     |    12 |
| WARNING   |    10 |
| **Total** |**22** |

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
Fix `express-sequelize-injection` first — it accounts for 6 findings across `routes/search.ts`, `routes/login.ts`, and several challenge codefixes, all sharing the same root cause: raw string interpolation into a Sequelize `query()` call. Fixing the pattern once at the route level (switching to parameterized `findAll()` with `where` clauses) closes all 6 findings simultaneously and directly corresponds to the High SQL Injection ZAP found at runtime. It's the highest-frequency rule, maps to a Critical OWASP category (A03), and has a clear fix — exactly the triage-shortcut criteria from Lecture 5 slide 8.

### False-positive sample
**File:** `labs/lab5/semgrep/juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts:5`
**Rule:** `express-sequelize-injection`
**Reason:** This file is a deliberately vulnerable code snippet that lives in the `data/static/codefixes/` directory — it's a teaching artifact shown to users as the "wrong" solution to a challenge, not application code that ever executes in production. The rule fires correctly on the pattern, but the finding is a false positive in the context of actual risk: no HTTP request can reach this file at runtime.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q='(` | `express-sequelize-injection` | `routes/search.ts:23` | **High** (both agree) |
| 2 | A03 Injection | SQL Injection | `/rest/user/login` | `express-sequelize-injection` | `routes/login.ts:34` | **High** (both agree) |

### Strongest correlation deep-dive

**Vulnerable code** (`routes/search.ts:23`):
```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```
The user-controlled `req.query.q` value flows directly into a raw SQL string via template literal — classic unsanitized injection.

**Working payload** (from ZAP auth report):
```
GET /rest/products/search?q='( HTTP/1.1
→ HTTP/1.1 500 Internal Server Error
```
The single quote + open parenthesis breaks the SQL syntax, causing Sequelize to throw and the server to return a 500 — confirming the injection point is live.

**Fix:**
```typescript
// Replace raw query with parameterized Sequelize findAll:
models.Products.findAll({
  where: {
    [Op.or]: [
      { name: { [Op.like]: `%${criteria}%` } },
      { description: { [Op.like]: `%${criteria}%` } }
    ],
    deletedAt: null
  },
  order: [['name', 'ASC']]
})
```
Sequelize's `findAll` with `Op.like` passes the value as a bound parameter — the DB driver escapes it before the query is executed, eliminating the injection surface entirely.

**Why both tools caught it:** SAST (Semgrep) found it because the data flow from `req.query.q` to `sequelize.query()` is syntactically visible in the source — no runtime needed. DAST (ZAP) found it because the endpoint is live, accepts HTTP requests, and the active scanner sent SQL metacharacters and observed a 500 error. Each tool validated the other's finding from a different angle: Semgrep proves the code is structurally vulnerable; ZAP proves it is exploitable at runtime.

### Reflection
Lecture 5 slide 15 calls correlated findings "highest-confidence" because neither tool can produce a false positive on a finding the other independently confirmed — SAST can't run the code, DAST can't read the source. In a real PR review, I would want the **SAST finding first**: it arrives at CI time (before merge), pinpoints the exact line, and gives the developer a precise fix location. The DAST evidence then serves as the post-deploy confirmation that the fix actually closed the exploitable path — not just that the code pattern changed.
