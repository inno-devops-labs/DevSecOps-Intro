# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: 2 minutes
- Total alerts: 10
| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: 8 minutes
- Total alerts: 12
| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 1.2×
- Did your run match the lecture's ratio? No, the ratio was significantly lower in this specific run, though the severity increased (found a High).
- Pick **two specific alerts** that only the authenticated scan found:
  1. **SQL Injection (High)**: The active scan performed deeper fuzzing on authenticated endpoints (like `/rest/user/login`) and parameters that are not fully exposed or reachable without a session.
  2. **Session ID in URL Rewrite (Medium)**: This is only detectable when the scanner can interact with session-management logic and observe how session identifiers are handled in responses.

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
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A03:2021 Injection |
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03:2021 Injection |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A05:2021 Security Misconfiguration |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01:2021 Broken Access Control |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01:2021 Broken Access Control |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A07:2021 Identification and Authentication Failures |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03:2021 Injection |

### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?
I would fix `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` first. It is the most frequent high-severity finding and represents a systemic risk of SQL injection across multiple endpoints. Fixing the data-access layer to use parameterized queries would eliminate 6 findings at once.

### False-positive sample
- **File**: `.github/workflows/update-challenges-ebook.yml`
- **Rule**: `yaml.github-actions.security.run-shell-injection.run-shell-injection`
- **Reason**: The "injection" point is in a CI/CD workflow file where the inputs are controlled by the repository maintainers, not by external untrusted users, making the risk negligible in this context.

---

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | /rest/products/search | sequelize-injection-express | routes/search.ts:23 | High (both agree) |
| 2 | A03 Injection | SQL Injection | /rest/user/login | sequelize-injection-express | routes/login.ts:34 | High (both agree) |

### Strongest correlation deep-dive
**Vulnerable Code (`routes/search.ts:23`):**
```typescript
models.sequelize.query(\`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name\`)
```

**Working Payload (ZAP):**
`'(` (leads to 500 Internal Server Error, indicating a syntax break in the SQL query)

**Proposed Fix:**
Use parameterized queries (replacements) provided by Sequelize:
```typescript
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name',
  {
    replacements: { search: `%${criteria}%` },
    type: QueryTypes.SELECT
  }
)
```

**Why both tools caught it:**
ZAP caught it dynamically by observing the server's error response to specially crafted characters (the "black-box" approach). Semgrep caught it statically by identifying a pattern where a template literal is used to concatenate user-controlled variables directly into a database query string (the "white-box" approach).

### Reflection (2-3 sentences)
I would prefer the DAST evidence first because it provides a "proof of concept" (working payload) that proves the vulnerability is actually exploitable in the running environment. SAST findings can be numerous and contain false positives, while a DAST finding is a confirmed security hole.
