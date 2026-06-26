# Lab 5 — SAST + DAST: Scanning Juice Shop From Both Angles

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~2 minutes
- Total alerts: 10 unique alert types

| Severity | Alert |
|----------|-------|
| Medium (High) | Content Security Policy (CSP) Header Not Set |
| Medium (Medium) | Cross-Domain Misconfiguration |
| Low (Medium) | Cross-Origin-Embedder-Policy Header Missing or Invalid |
| Low (Medium) | Cross-Origin-Opener-Policy Header Missing or Invalid |
| Low (Low) | Dangerous JS Functions |
| Low (Medium) | Deprecated Feature Policy Header Set |
| Informational (Medium) | Modern Web Application |
| Informational (Medium) | Storable and Cacheable Content |
| Informational (Medium) | Storable but Non-Cacheable Content |
| Low (Low) | Timestamp Disclosure - Unix |

### Authenticated full scan
- Duration: ~8 minutes (spider 18s + Ajax spider 1m11s + passive scan 13s + active scan 6m15s)
- Total alerts: 12 unique alert types

| Severity | Alert |
|----------|-------|
| High (Low) | SQL Injection |
| Medium (High) | Content Security Policy (CSP) Header Not Set |
| Medium (High) | Session ID in URL Rewrite |
| Medium (Medium) | Cross-Domain Misconfiguration |
| Medium (Medium) | Missing Anti-clickjacking Header |
| Low (Medium) | Private IP Disclosure |
| Low (Medium) | X-Content-Type-Options Header Missing |
| Low (Low) | Timestamp Disclosure - Unix |
| Informational (High) | Authentication Request Identified |
| Informational (Medium) | Modern Web Application |
| Informational (Medium) | Session Management Response Identified |
| Informational (Medium) | User Agent Fuzzer |

### The "10–20× more" claim (Lecture 5 slide 11)

The lecture's 10–20× claim refers to total alert instances (not unique alert types), which is more dramatic when the authenticated scanner can reach POST endpoints, user-specific routes, and admin functionality. In our run the authenticated scan found 12 unique alert types vs the baseline's 10 — a modest increase at the type level. However the quality difference is more significant than the quantity: the authenticated scan discovered **SQL Injection (High)** which was completely invisible to the baseline scanner because the vulnerable search endpoint requires the app to be crawled as a logged-in user before ZAP's active scanner can probe it. The baseline scan also missed **Session ID in URL Rewrite** and **Missing Anti-clickjacking Header**, both of which only appear on authenticated routes. The 10–20× ratio applies more to enterprise apps with large authenticated surfaces; Juice Shop's relatively small authenticated footprint explains the smaller multiplier here.

**Two alerts only the authenticated scan found:**

1. **SQL Injection — High (Low)** — The vulnerable `/rest/products/search?q=` endpoint is linked from the product listing page, which the spider only reaches after logging in. The baseline crawler never authenticated, so it never discovered the search route and ZAP's active SQL injection payloads were never fired against it.

2. **Session ID in URL Rewrite — Medium (High)** — This alert fires on authenticated session management responses where the session token appears in a URL parameter. The baseline scan has no session token (it's unauthenticated), so there is nothing to detect; the alert only becomes reachable once ZAP logs in and receives a session-bearing response.

---

## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| **Total** | **22** |

### Top 10 rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A03 — Injection |
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03 — Injection |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A05 — Security Misconfiguration |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01 — Broken Access Control |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 — Broken Access Control |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A02 — Cryptographic Failures |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03 — Injection |

### Triage shortcut (Lecture 5 slide 8)
The single rule to fix first is `express-sequelize-injection` (6 findings). It fires on Sequelize ORM calls where user-controlled input flows directly into a query without parameterization — the exact class of bug that ZAP's authenticated scan confirmed as exploitable via SQL Injection (High). A single fix at the query-builder layer (switching to parameterized Sequelize `where` clauses or using `literal()` with bound parameters) closes all 6 findings at once, and the cross-tool confirmation from ZAP makes this the highest-confidence, highest-severity item in the entire lab.

### False-positive sample
**Rule:** `yaml.github-actions.security.run-shell-injection.run-shell-injection`
**File:** `.github/workflows/*.yml` (GitHub Actions workflow files in the Juice Shop repo)
**Reason:** Semgrep flags `${{ github.event.* }}` interpolations in `run:` steps as potential shell injection, but these workflow files are part of Juice Shop's own CI pipeline and the interpolated values come from GitHub's controlled event context (branch names, PR titles) rather than untrusted external user input. In a read-only CI context where external contributors cannot control the triggering event payload, these are informational at best — not actionable injection sinks.

---

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file | Confidence |
|---|-----------|-----------|---------|--------------|--------------|------------|
| 1 | A03 — Injection | SQL Injection (High) | `/rest/products/search?q=` | `express-sequelize-injection` | `routes/search.ts` | High — both tools independently confirm unsanitized input reaching the database layer |

### Strongest correlation deep-dive

**Vulnerable code (Semgrep finding — `routes/search.ts`):**
Sequelize's `where` clause receives a raw string built by concatenating the `q` query parameter directly into the SQL fragment, e.g.:
```javascript
models.sequelize.query(
  `SELECT * FROM Products WHERE name LIKE '%${req.query.q}%'`
)
```

**Working payload (ZAP finding):**
ZAP's active scanner confirmed the endpoint is injectable by sending:
```
GET /rest/products/search?q='))--
```
and observing a 200 response with database error output or unexpected record return, confirming the raw input reaches the SQL engine unsanitized.

**The fix — parameterized query:**
```javascript
models.sequelize.query(
  `SELECT * FROM Products WHERE name LIKE :search`,
  { replacements: { search: `%${req.query.q}%` }, type: models.sequelize.QueryTypes.SELECT }
)
```
Using Sequelize's named replacements ensures the user-supplied value is always treated as a data literal, never as SQL syntax.

**Why both tools caught it:**
Semgrep detected the static data flow — user input from `req.query` concatenated directly into a Sequelize query string — without executing the code. ZAP confirmed it dynamically by sending injection payloads through the running app and observing anomalous responses. The two tools are complementary: Semgrep finds the pattern in code before deployment; ZAP proves it is exploitable at runtime. Together they provide the highest-confidence finding type because neither false-positive scenario (Semgrep finding dead code, ZAP finding a WAF artifact) applies when both agree.

### Reflection
Lecture 5 slide 15 calls the correlated finding the "highest-confidence finding type" because each tool eliminates the other's main weakness: SAST can flag code that is never actually reachable, and DAST can flag behavior caused by infrastructure rather than the application code itself. In a real PR review, the SAST finding should come first — it points the developer to the exact file and line to fix, making remediation immediate and precise. The DAST evidence then serves as proof of exploitability, which is what escalates the finding from "potential issue" to "confirmed vulnerability requiring immediate patching" in the risk register.
