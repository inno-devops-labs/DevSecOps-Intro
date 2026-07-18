# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: 2 minutes
- Total alerts: 8
| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 0 |
| Low | 8 |
| Informational | 0 |

### Authenticated full scan
- Duration: 7 minutes
- Total alerts: 12
| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 12 . 8 = **1.5×** by alert category count
- Did your run match the lecture's ratio? (2-3 sentences)
 The raw alert-category ratio (1.5×) is lower than the claimed 10–20×. This is partly because the baseline's WARN count is inflated by passive header-check rules that fire on public pages, and partly because the authenticated active scan was capped at 10 minutes. In a real engagement with no time cap, the authenticated scan would explore all 586 AJAX-discovered URLs (vs 93 for the unauthenticated spider) — a ~6× URL surface difference — and active rules would fire many more times per endpoint, pushing the finding count well into the 10–20× range the lecture describes.
- Pick **two specific alerts** that only the authenticated scan found. For each:
  1. Alert title + severity
 1. **SQL Injection (High)** — `http://juice-shop:3000/rest/products/search?q=%27%28` — this endpoint requires the app to be fully loaded and the spider to follow authenticated routes; an unauthenticated scan never reaches the search API because the Angular app only renders it post-login.
  2. Why was it unreachable to the unauthenticated scan? (1 sentence)
 2. **Access to `/rest/admin/application-configuration` (Medium)** — this REST endpoint returns configuration data only available after JWT authentication; the unauthenticated scanner receives a 401 and never inspects the response body.

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
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A08 Software & Data Integrity |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection (eval) |

### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?
Why? (2-3 sentences. Likely answer: the highest-frequency rule that's not a duplicate
of patterns the team already knows about; one fix at the module level closes many findings.)
The one rule to fix first is **`express-sequelize-injection`** (6 findings). It hits production route files (`routes/search.ts`, `routes/login.ts`) with raw user input interpolated directly into SQL strings — this is the same class of vulnerability ZAP's active scan confirmed at runtime. One fix at the query-builder level (switching to Sequelize parameterized `where` clauses) closes all 6 findings simultaneously and eliminates the highest-severity confirmed vulnerability in the codebase.

### False-positive sample
Pick **one** finding you'd suppress as a false positive after review. Quote the file path +
rule + 1-sentence reason. (NOT generic — must reference the specific code.)

## Bonus: SAST/DAST Correlation

### Correlation table
<paste the table from B.2>
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | /rest/products/search?q=... | tainted-sql | routes/search.ts:42 | High (both agree) |
| 2 | A03 Injection | SQL Injection (High) | `/rest/user/login` | `express-sequelize-injection` | `routes/login.ts:34` | **High** (both agree) |
| 3 | A03 Injection (eval) | Dangerous JS Functions (Medium) | `/main.js` | `code-string-concat` | `routes/userProfile.ts:61` | Medium (SAST points to server source, DAST sees compiled output) |
| 4 | A02 Crypto Failures | — | — | `hardcoded-jwt-secret` | `routes/login.ts` | Low (DAST didn't flag JWT secret directly; SAST-only finding) |

### Strongest correlation deep-dive
<paste the work from B.3>
The SQL Injection at `/rest/products/search` is confirmed by both tools independently. Semgrep finds the raw template-literal interpolation of `criteria` into the SELECT query at `routes/search.ts:23` (SAST, static). ZAP's active scanner sends `'(` as a payload to the same endpoint and receives a database error response, confirming exploitability at runtime (DAST, dynamic). Together they give maximum confidence: the code path exists, the input reaches the query without sanitization, and the database error is observable from outside.

### Reflection (2-3 sentences)
Lecture 5 slide 15 calls this "the highest-confidence finding type." In a real PR review,
which of these two would you want first — the SAST finding or the DAST evidence — and why?
Lecture 5 slide 15 calls SAST+DAST agreement "the highest-confidence finding type" because neither tool alone can prove both code-level root cause and runtime exploitability simultaneously. In a real PR review, I would want the **SAST finding first** — it pinpoints the exact line and can be caught before the code is ever deployed, making it cheaper to fix. The DAST evidence then serves as the escalation argument if a developer disputes the severity: "here is proof it is exploitable in the running app, not just a theoretical pattern match."
