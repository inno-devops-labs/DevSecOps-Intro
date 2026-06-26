# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: **3 minutes** (204 s)
- Total alerts: **10**
| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: **6 minutes** (332 s)
- Total alerts: **12**
| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): **1.2×** (12 / 10)
- Our run did **not** match the lecture's 10–20× ratio on raw alert-type count. Juice Shop's public surface is already small and intentionally over-exposed, so the baseline spider still hits most unauthenticated routes. The authenticated scan's real gain shows up in **new alert types** (8 types only auth found) and crawl depth (AJAX spider: 550 URLs vs spider: 93 URLs), including **High SQL Injection** and admin-only endpoints. On a typical enterprise app with large post-login surface, the multiplier is much higher because baseline cannot reach authenticated routes at all.
- **Auth-only alert 1:** **SQL Injection** (High) on `/rest/products/search?q=…` — the search endpoint is reachable without login, but ZAP's authenticated active scan with a logged-in session exercised it with SQLi payloads and confirmed a 500 error; baseline passive scan did not flag this as SQL Injection.
- **Auth-only alert 2:** **Private IP Disclosure** (Low) on `/rest/admin/application-configuration` — this admin configuration endpoint requires an authenticated admin session; the unauthenticated baseline scan never receives the response body containing `192.168.99.100:3000`.

---

## Task 2: SAST with Semgrep

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
I would fix **`express-sequelize-injection`** first (6 findings). It is the highest-frequency production-route rule (not CI workflow noise), maps directly to OWASP A03, and a single remediation pattern — parameterized queries via Sequelize `replacements` — closes multiple real SQLi sinks in `routes/search.ts`, `routes/login.ts`, and related handlers.

### False-positive sample
- **File:** `labs/lab5/semgrep/juice-shop/data/static/codefixes/unionSqlInjectionChallenge_1.ts:6`
- **Rule:** `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
- **Reason:** This file is a static **code-fix challenge snippet** shown to players in the training UI, not executable production code — the vulnerable query is intentional didactic content, not a deployable route.

---

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q='(` | `express-sequelize-injection` | `routes/search.ts:23` | High (both agree) |
| 2 | A03 Injection | SQL Injection | `/rest/user/login` (param: `email`) | `express-sequelize-injection` | `routes/login.ts:34` | High (both agree) |

### Strongest correlation deep-dive

**Vulnerable code** (`routes/search.ts:23`):
```typescript
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

**Working payload** (from ZAP auth report):
```
GET /rest/products/search?q='(
Attack: '(
Evidence: HTTP/1.1 500 Internal Server Error
```

**Fix:**
```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`,
  { replacements: { criteria: `%${criteria}%` } }
)
```

**Why both tools caught it:** Semgrep statically traces `req.query.q` into the Sequelize query string template (SAST). ZAP's authenticated active scan sent `'` in the `q` parameter and observed a 500 error response, confirming runtime exploitability (DAST). Static analysis found the sink; dynamic analysis confirmed the injection point responds to malformed input.

### Reflection (2-3 sentences)
Lecture 5 slide 15 calls this "the highest-confidence finding type." In a real PR review I would want the **DAST evidence first** — it proves the vulnerability is reachable and exploitable in the running app — but I would not merge without the **SAST finding**, because it pinpoints the exact file and line for the fix. Together they eliminate both "false positive code path" and "false negative in production config" doubts.
