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
- Duration: ~10 minutes (active scan capped at 10 min)
- Total alerts: 12

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 12 / 10 = **1.2×**
- My run did NOT hit the lecture's 10–20×, which is expected for Juice Shop with a time-capped
  scan. Juice Shop is a single-page app whose REST API is largely reachable without logging in,
  so the unauthenticated baseline already sees most of the surface; ZAP also reports alert
  *types* (not individual instances), which compresses the gap, and the active scan was capped
  at 10 minutes. The direction still matches the lecture — authenticated scanning surfaced more
  (the only High-severity alert and extra Medium alerts appeared only after login), because the
  post-auth routes (basket, orders, admin) are only reachable once ZAP holds a valid session token.
- Two alerts only the authenticated scan found:
  1. SQL Injection (High) — unreachable to baseline because the active scanner only injected into
     the product-search query parameter while crawling as a logged-in user; the anonymous baseline
     didn't drive the same authenticated request flow, so the injectable endpoint wasn't exercised.
  2. Missing Anti-clickjacking Header (Medium) — unreachable to baseline because it was reported on
     a post-login page that the authenticated spider reached only after holding a valid session,
     which the anonymous baseline never crawled.

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
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A03 Injection |
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03 Injection |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A05 Security Misconfiguration |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01 Broken Access Control |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 Broken Access Control |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A02 Cryptographic Failures |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)
I'd fix **express-sequelize-injection** first. It's the highest-frequency rule (6 of 22 findings)
and maps to A03 SQL injection — the most damaging class in the list. Because all 6 hits share one
root cause (untrusted input concatenated into Sequelize queries), a single fix at the data-access
layer (parameterized queries / Sequelize replacement binding, routed through one helper) closes all
six at once — the best ratio of effort to risk reduced, and it hardens every query path instead of
patching one line.

### False-positive sample
Finding I'd suppress after review: **.github/workflows/update-challenges-ebook.yml:22** flagged by
**yaml.github-actions.security.run-shell-injection.run-shell-injection**. Reason: this fires on the
project's own GitHub Actions CI workflow, not on the running application — the shell step
interpolates trusted GitHub-context values, not attacker-controlled HTTP input, so it isn't part of
the deployed Juice Shop's exploitable attack surface and is out of scope for this app assessment.

---

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | /rest/products/search?q=%27%28 | express-sequelize-injection | routes/search.ts:23 | High (both agree) |
| 2 | A03 Injection | SQL Injection | /rest/user/login (auth bypass) | express-sequelize-injection | routes/login.ts:34 | Medium (DAST on search, SAST flags login too) |

### Strongest correlation deep-dive
1. **Vulnerable code** (Semgrep — `routes/search.ts:23`): untrusted `criteria` from the request
   query is concatenated straight into a raw Sequelize SQL string instead of being passed as a
   bound parameter, so the `q` value becomes part of the SQL statement.
2. **Working payload** (ZAP): `GET /rest/products/search?q=%27%28` — the `q` parameter is set to
   `'(` , which breaks out of the string literal and yields `HTTP/1.1 500 Internal Server Error`,
   confirming the input reaches the SQL engine unsanitized.
3. **The fix:** stop string-concatenating user input into the query. Use a parameterized /
   bound query (Sequelize `replacements` or the ORM's query builder) so `q` is always treated as
   data, never as SQL. Add input validation/escaping at the route as defense in depth.
4. **Why both tools caught it:** Semgrep saw, statically, untrusted input flowing into a SQL sink
   without sanitization (the *cause*), and ZAP independently proved, dynamically, that the same
   endpoint was exploitable over live HTTP via a 500 on a broken-quote payload (the *effect*).

### Reflection (2-3 sentences)
A finding both tools agree on is the highest-confidence type because static and dynamic analysis
fail in opposite ways: SAST can flag code paths that aren't actually reachable at runtime (false
positives), while DAST can miss vulnerabilities it never crawled (false negatives). In a real PR
review I'd want the **DAST evidence first** — the `q='(` payload returning a 500 is undeniable proof
of exploitability and instantly justifies blocking the merge — and then use the **Semgrep file:line
(routes/search.ts:23)** to point the developer straight at the exact line to fix. Together they turn
"maybe a problem" into "confirmed, and here's where."

