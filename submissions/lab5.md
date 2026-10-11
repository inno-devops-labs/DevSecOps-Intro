# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: 1.5 minutes
- Total alerts: 10

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: 4.5 minutes
- Total alerts: 12

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 1.2×
- Did your run match the lecture's ratio? 
  No, my run showed a ratio of 1.2× for unique alert *types*. The lecture's claim likely refers to the sheer volume of vulnerable *instances* (URLs/parameters), as an authenticated crawler accesses exponentially more pages behind the login. Our script only counted unique risk categories.
- Pick **two specific alerts** that only the authenticated scan found. For each:
  1. **SQL Injection (High)**
     - Why was it unreachable to the unauthenticated scan? The vulnerable endpoint or parameter is located behind the login barrier, so the baseline crawler couldn't reach the page to inject the payload.
  2. **Session ID in URL Rewrite (Medium)**
     - Why was it unreachable to the unauthenticated scan? This vulnerability relies on a user session being actively established; since the baseline scan does not log in, it cannot trigger or observe session management flaws.





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
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01 |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A01 |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 |

### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?
I would fix `express-sequelize-injection` first. It has the highest frequency among the vulnerabilities found and represents a severe flaw (SQL Injection - A03), meaning fixing the parameter binding at the ORM level here would quickly eliminate a large cluster of critical vulnerabilities.

### False-positive sample
File path: `data/static/codefixes/unionSqlInjectionChallenge_1.ts`
Rule: `express-sequelize-injection`
Reason: This file is just a static fixture containing code snippets used to display code fixes in the UI; it's not actually executed by the backend, making this finding a false positive.






  ## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q=...` | `express-sequelize-injection` | `routes/search.ts:23` | High (both agree) |
| 2 | A03 Injection | SQL Injection | `/rest/user/login` (email) | `express-sequelize-injection` | `routes/login.ts:34` | High (both agree) |

### Strongest correlation deep-dive
**1. Vulnerable code (from `routes/search.ts:23`)**
```typescript
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

**2. Working payload (from ZAP report)**
```
URL: http://juice-shop:3000/rest/products/search?q=%27%28
Parameter: q
Attack: '(
```

**3. The fix**
Use parameterized queries (bind variables) instead of string interpolation:
```typescript
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
  { replacements: { criteria: `%${criteria}%` } }
)
```

**4. Why both tools caught it**
Semgrep caught it because the code directly interpolates a user-controlled variable (`criteria` from `req.query.q`) into a raw SQL query string inside the `sequelize.query` call—a classic static pattern. ZAP caught it because during its active crawl it injected SQL metacharacters like `'(` into the `q` parameter and observed a database syntax error or unexpected behavior in the response.

### Reflection (2-3 sentences)
Lecture 5 slide 15 calls this "the highest-confidence finding type." In a real PR review, I would want the **SAST finding** first. SAST points exactly to the file and line number (`routes/search.ts:23`), which makes it trivial for a developer to implement a fix immediately. The DAST evidence is then incredibly valuable to prove the exploitability of the finding and to verify that the fix actually resolved the issue at runtime.