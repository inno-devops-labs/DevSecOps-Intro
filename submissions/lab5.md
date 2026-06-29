# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Total alerts: 10
| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

Alert types found: Content Security Policy (CSP) Header Not Set, Cross-Domain Misconfiguration, Cross-Origin-Embedder-Policy Header Missing or Invalid, Cross-Origin-Opener-Policy Header Missing or Invalid, Dangerous JS Functions, Deprecated Feature Policy Header Set, Modern Web Application, Storable and Cacheable Content, Storable but Non-Cacheable Content, Timestamp Disclosure - Unix.

### Authenticated full scan
- Total alerts: 12
| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

Alert types found: Authentication Request Identified, Content Security Policy (CSP) Header Not Set, Cross-Domain Misconfiguration, Missing Anti-clickjacking Header, Modern Web Application, Private IP Disclosure, **SQL Injection**, Session ID in URL Rewrite, Session Management Response Identified, Timestamp Disclosure - Unix, User Agent Fuzzer, X-Content-Type-Options Header Missing.

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): **1.2× (12 / 10)**
- My run did not match the lecture's 10-20× ratio. The reason is most likely scope: this run used the default `maxScanDurationInMins: 15` active-scan window and a 5-10 minute spider, which is enough to authenticate and reach a modest set of authenticated routes (cart, profile, search, login) but not enough to deeply crawl every admin/business-logic endpoint Juice Shop exposes. A longer active-scan duration and a spider that follows more AJAX-driven routes would likely surface a much larger gap between the two scans, closer to the lecture's figure.
- Two specific alerts only the authenticated scan found:
  1. **SQL Injection** (High) — unreachable to the unauthenticated scan because the vulnerable endpoint (`/rest/products/search?q=...`) and the login POST body (`/rest/user/login`, `email` param) only get actively fuzzed once ZAP has a valid session to follow through the spidered, authenticated user flow; the baseline scan's spider never logs in, so it never reaches the parameterized search/login calls with attacker-controlled values.
  2. **Missing Anti-clickjacking Header** (Medium, on `/socket.io/...` polling endpoints) — these Socket.IO long-polling URLs are only generated once an authenticated session establishes a live connection (cart updates, notifications), so the unauthenticated baseline crawl never requests them and therefore never sees the missing header on that response.

---

## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| **Total** | 22 |

### Top rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A03 Injection |
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03 Injection (CI/CD context) |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A05 Security Misconfiguration |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01 Broken Access Control |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 Broken Access Control |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A02 Cryptographic Failures |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)
The rule to fix first is `express-sequelize-injection`, with 6 hits — the highest frequency of any rule in this run. It appears across `routes/login.ts`, `routes/search.ts`, and four files under `data/static/codefixes/`, all sharing the same root cause: raw template-string interpolation into `sequelize.query()` instead of parameterized binding. Because the pattern is identical everywhere it fires, a single fix at the module level — wrapping the query builder to enforce bound parameters — would close all 6 findings at once rather than patching each call site individually.

### False-positive sample
`labs/lab5/semgrep/juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts:5` — flagged by `express-sequelize-injection`. This file is one of Juice Shop's intentional "codefix challenge" snippets shipped specifically to teach learners to spot and fix SQL injection; it is never wired into a live route and is not reachable from any HTTP request in the running application, so in a real triage it would be suppressed as a false positive (or more precisely, a true-positive-but-out-of-scope finding) rather than scheduled for remediation alongside the live `routes/search.ts` and `routes/login.ts` findings.

---

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q=%27%28` | express-sequelize-injection | routes/search.ts:23 | High (both agree) |
| 2 | A03 Injection | SQL Injection | `/rest/user/login` (param: email) | express-sequelize-injection | routes/login.ts:34 | High (both agree) |

### Strongest correlation deep-dive

**1. Vulnerable code** (`routes/login.ts:34`, found by Semgrep):
```ts
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND
password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

**2. Working payload** (from ZAP's authenticated SQL Injection alert):
```
POST /rest/user/login
param: email
attack: '
evidence: HTTP/1.1 500 Internal Server Error
```
ZAP's `search.ts` finding used the same attack pattern against the GET `q` parameter: `GET /rest/products/search?q='(`, also returning a 500.

**3. The fix:**
```ts
models.sequelize.query(
  'SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL',
  { replacements: [req.body.email || '', security.hash(req.body.password || '')], model: UserModel, plain: true }
)
```
Switching from template-string interpolation to Sequelize's `replacements` array forces the driver to bind parameters rather than concatenate raw input into the SQL string, which is the standard parameterized-query fix referenced in both ZAP's solution text and the OWASP SQL Injection Prevention Cheat Sheet.

**4. Why both tools caught it:** Semgrep caught it statically because the taint-tracking rule could trace `req.body.email` flowing directly into a template literal passed to `sequelize.query()` without ever crossing a sanitization or parameterization boundary. ZAP caught it dynamically because sending a single unescaped quote (`'`) as the live `email` value broke the SQL syntax and triggered an observable HTTP 500 — the same root cause is visible from the source-code angle (data flow) and the black-box angle (a behavioral side effect).

### Reflection
Lecture 5 slide 15 calls this "the highest-confidence finding type." In a real PR review, I would want the **SAST finding first** — it points to the exact file and line (`routes/login.ts:34`) and the fix is immediately actionable in the diff, whereas the DAST evidence (a 500 error from a single quote) only tells you *that* something is broken, not *where*. The DAST evidence is still valuable as proof that the issue is exploitable in the running application rather than theoretical, which is exactly what makes the combination of the two reports more convincing than either alone.
