# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~1-2 minutes
- Total alerts: 5
| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 1 |
| Low | 3 |
| Informational | 1 |

### Authenticated full scan
- Duration: ~4 minutes 16 seconds
- Total alerts: 74
| Severity | Count |
|----------|------:|
| High | 6 |
| Medium | 18 |
| Low | 40 |
| Informational | 10 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 14.8×
- Did your run match the lecture's ratio?: Yes, the authenticated scan found nearly 15 times more alerts than the baseline scan. This perfectly demonstrates the lecture's claim that without authentication, a DAST scanner can only access superficial surface areas (like login pages or public assets) and misses the core business logic.
- Pick **two specific alerts** that only the authenticated scan found. For each:
  1. **SQL Injection on `/rest/products/search` (High)**: This endpoint is part of the application's internal API and was only thoroughly fuzzed once the scanner had a valid session token to access deeper functionality.
  2. **Insecure Direct Object Reference (IDOR) on User Profile (Medium)**: The unauthenticated scanner could not reach user profile components at all, as any attempt to access them without a JWT results in a 401 Unauthorized redirect.

---

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
| `javascript.sequelize.security.audit.sequelize-injection-express` | 6 | A03:2021-Injection |
| `yaml.github-actions.security.run-shell-injection` | 5 | A03:2021-Injection |
| `javascript.express.security.audit.express-check-directory-listing` | 4 | A01:2021-Broken Access Control |
| `javascript.express.security.audit.express-res-sendfile` | 4 | A01:2021-Broken Access Control |
| `javascript.express.security.audit.express-open-redirect` | 1 | A01:2021-Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode` | 1 | A02:2021-Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat` | 1 | A03:2021-Injection |

### Triage shortcut (Lecture 5 slide 8)
If I had time to fix only one issue, I would address `javascript.sequelize.security.audit.sequelize-injection-express`. It is the most frequent ERROR-level finding (6 occurrences). Fixing the underlying pattern for how Sequelize handles database queries at the ORM/module level would close multiple vulnerabilities across different endpoints simultaneously.

### False-positive sample
File: `labs/lab5/semgrep/juice-shop/.github/workflows/update-challenges-ebook.yml`
Rule: `yaml.github-actions.security.run-shell-injection.run-shell-injection`
Reason: Semgrep flags `${{ github.ref_name }}` as a potential shell injection vector. However, in this specific context, the pipeline only runs on protected branches managed by administrators, meaning the branch name cannot be maliciously controlled by external contributors, making the risk strictly theoretical here.

---

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q=%27%28` | `sequelize-injection-express` | `routes/search.ts` | High (both agree) |
| 2 | A01 Access Control | Directory Browsing | `/ftp` | `express-check-directory-listing` | `routes/fileServer.ts` | High (both agree) |

### Strongest correlation deep-dive
**1. Vulnerable code (Semgrep in `routes/search.ts`):**
```typescript
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${req.query.q}%' OR description LIKE '%${req.query.q}%') AND deletedAt IS NULL) ORDER BY name`)
```

**2. Working payload (ZAP):**
```text
GET /rest/products/search?q=%27%28
```

**3. Proposed fix:**
Replace string concatenation with parameterized queries natively supported by Sequelize to safely escape user input:
```typescript
models.sequelize.query('SELECT * FROM Products WHERE ((name LIKE :query OR description LIKE :query) AND deletedAt IS NULL) ORDER BY name', {
  replacements: { query: `%${req.query.q}%` }
})
```

**4. Why both tools caught it:**
Semgrep caught this because it explicitly detected the untrusted `req.query.q` variable being interpolated directly into a `sequelize.query` string. ZAP caught this dynamically because sending the payload `%27%28` (an encoded apostrophe and parenthesis) caused the database to return a SQL syntax error, proving the injection was successful.

### Reflection
In a real PR review, I would want the **SAST finding** first. While DAST provides excellent proof of exploitability (which helps prioritize the fix), SAST points me directly to the exact file and line number (e.g., `routes/search.ts`). Without SAST, I would have to manually trace the DAST `/rest/products/search` URI through the routing logic to find the vulnerable code.
