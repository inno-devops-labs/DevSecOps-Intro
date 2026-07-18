# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: **~2 minutes**
- Total alerts: **28**
| Severity | Count |
|----------|------:|
| High | 2 |
| Medium | 9 |
| Low | 11 |
| Informational | 6 |

### Authenticated full scan
- Duration: **~8 minutes**
- Total alerts: **412**
| Severity | Count |
|----------|------:|
| High | 18 |
| Medium | 94 |
| Low | 187 |
| Informational | 113 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): **14.7×** (412 / 28)
- The lecture claim held for this run: authenticated crawling reached basket, orders, admin-adjacent REST routes, and token-bearing API calls that the spider never touches without a session. Baseline still caught surface issues (missing headers, cookie flags) but missed most business-logic and auth-gated paths.
- **Auth-only alert 1:** *SQL Injection* (High) on `/rest/products/search?q=...` — requires no special role but the authenticated spider discovered the search parameter through logged-in navigation paths the baseline spider deprioritized.
- **Auth-only alert 2:** *Cross Site Scripting (Reflected)* (Medium) on `/rest/user/authentication-details/` — only reachable after login; baseline scan never obtained a session cookie so ZAP never requested this endpoint.

---

## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | 47 |
| WARNING | 128 |
| INFO | 31 |
| **Total** | **206** |

### Top 10 rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| javascript.express.security.audit.xss.direct-response-write | 24 | A03 |
| javascript.lang.security.audit.path-traversal.path-join-resolve-traversal | 19 | A01 |
| javascript.express.security.injection.tainted-sql | 14 | A03 |
| generic.secrets.security.detected-jwt-token | 11 | A02 |
| javascript.express.security.cors.cors-misconfiguration | 9 | A05 |
| javascript.express.security.audit.express-check-csurf-middleware-usage | 8 | A01 |
| javascript.lang.security.audit.unsafe-formatstring | 7 | A03 |
| typescript.react.security.audit.react-dangerouslysetinnerhtml | 6 | A03 |
| javascript.express.security.injection.tainted-html-string | 5 | A03 |
| generic.nginx.security.missing-security-headers | 4 | A05 |

### Triage shortcut (Lecture 5 slide 8)
Fix **`javascript.express.security.injection.tainted-sql`** first — 14 hits across search/basket routes, maps to **A03 Injection**, and one parameterized-query refactor at the data-access layer collapses many duplicate findings. XSS rules fire often in Juice Shop by design, but SQLi in `/rest/products/search` is exploitable with a single request and aligns with both DAST and SBOM priority (sqlite + express stack from Lab 4).

### False-positive sample
- **File:** `data/static/users.yml` + rule `generic.secrets.security.detected-jwt-token` — Semgrep flags hardcoded-looking strings in seed user fixtures that are intentional challenge data, not production secrets in runtime config. Would suppress with path exclude `data/static/**` after human review, not blind `--suppress`.

---

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q=apple')--` | `javascript.express.security.injection.tainted-sql` | `routes/search.ts:18` | High (both agree) |
| 2 | A03 Injection | Cross Site Scripting (Reflected) | `/rest/products/1/reviews` | `javascript.express.security.audit.xss.direct-response-write` | `routes/productReviews.ts:31` | Medium-High |

### Strongest correlation deep-dive (SQL Injection)

**Vulnerable code (Semgrep):**
```typescript
// routes/search.ts (simplified)
db.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`)
```

**Working payload (ZAP):**
```
GET /rest/products/search?q=')%20OR%201=1--
```

**Proposed fix:**
```typescript
db.sequelize.query(
  `SELECT * FROM Products WHERE name LIKE :criteria`,
  { replacements: { criteria: `%${criteria}%` }, type: QueryTypes.SELECT }
)
```

**Why both tools caught it:** Semgrep traces user input (`criteria`) into a raw SQL string without sanitization (static taint). ZAP sends malicious `q` and observes expanded result sets / DB errors in the HTTP response (dynamic proof). Together they give root cause + exploitability — the highest-confidence finding type from Lecture 5 slide 15.

### Reflection
In a real PR review I'd want **DAST evidence first** for merge-blocking (proven exploit against the running build), then **SAST** to locate the exact line for the fix. SAST alone can over-report on Juice Shop; DAST alone lacks file:line precision. The correlation row is what I'd paste into the security review comment.
