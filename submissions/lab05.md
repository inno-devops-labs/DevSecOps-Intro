# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: <2 minutes>
- Total alerts: <10>
| Severity | Count |
|----------|------:|
| High | <0> |
| Medium | <2> |
| Low | <5> |
| Informational | <3> |

### Authenticated full scan
- Duration: <5 minutes>
- Total alerts: <12>
| Severity | Count |
|----------|------:|
| High | <1> |
| Medium | <4> |
| Low | <3> |
| Informational | <4> |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): <1.2×>
- Did your run match the lecture's ratio? (2-3 sentences) No, the activeScan stage was limited to 5 minutes (instead of the default 15) because the ZAP container was being OOM-killed on my Mac, so the scanner did not get enough time to exercise the deeper authenticated routes. Still, the qualitative effect the slide describes did show up: the auth scan surfaced a High-severity alert (SQL Injection) that baseline could not see at all, which is the more important signal than the raw count ratio.
- Pick **two specific alerts** that only the authenticated scan found. For each:
  1. Alert title + severity:
  1.1 SQL Injection + High
  1.2 Session ID in URL Rewrite + Medium
  2. Why was it unreachable to the unauthenticated scan? (1 sentence)
  2.1 `zap-baseline.py` only runs passive checks
  2.2 by def: this alert fires when ZAP observes a session token being passed in the URL instead of a cookie, and baseline never authenticates

## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | <12> |
| WARNING | <10> |
| INFO | <?> | #INFO findings were filtered out at scan time via `--severity ERROR --severity WARNING`, per the assignment's command in 5.7
| **Total** | <22> |

### Top 10 rules by frequency (Semgrep returned only 7 distinct rules across all 22 findings under the assignment's filter `--severity ERROR --severity WARNING`
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| <javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection> | <6> | A03 Injection |
| <yaml.github-actions.security.run-shell-injection.run-shell-injection> | <5> | A03 |
| <javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing> | <4> | A05 Security Misconfiguration |
| <javascript.express.security.audit.express-res-sendfile.express-res-sendfile> | <4> | A01 Broken Access Control |
| <javascript.express.security.audit.express-open-redirect.express-open-redirect> | <1> | A01 Broken Access Control |
| <javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret> | <1> | A02 Cryptographic Failures |
| <javascript.lang.security.audit.code-string-concat.code-string-concat> | <1> | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?
express-sequelize-injection
Why? (2-3 sentences. Likely answer: the highest-frequency rule that's not a duplicate
of patterns the team already knows about; one fix at the module level closes many findings.)
It is the highest-frequency rule and sits in the highest-severity OWASP category - A03 Injection, and it is the same defect that the DAST scan independently confirmed as a runtime High on /rest/products/search and /rest/user/login. Slide 8 frames SAST's failure modes around false positives, false negatives, reachability blindness, etc. — and the DAST corroboration is what eliminates the "reachability blindness" worry for this specific rule: I know the vulnerable function is reached because ZAP exploited it. One module-level fix — switching the affected models.sequelize.query call sites to parameterized queries — closes 6 of the 22 findings at once.

### False-positive sample
Pick **one** finding you'd suppress as a false positive after review. Quote the file path +
rule + 1-sentence reason. (NOT generic — must reference the specific code.)
`data/static/codefixes/unionSqlInjectionChallenge_1.ts:6` - rule `express-sequelize-injection`. This file is part of the Juice Shop "code-fixes" directory, which intentionally ships vulnerable and fixed snippets side by side as part of the educational content.

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | /rest/products/search?q=%27%28 | express-sequelize-injection | routes/search.ts:23 | High (both agree) |
| 2 | A03 Injection | SQL Injection | /rest/user/login | express-sequelize-injection | routes/search.ts:34 | High (both agree) |

### Strongest correlation deep-dive 
For your strongest correlation (the one with highest severity in both reports):

Paste the vulnerable code from Semgrep's file:line
// routes/search.ts:19-23
export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)

Paste a working payload from ZAP's report
GET /rest/products/search?q=%27%28
URL-decoded: `q='(` — the classic "break out of the string literal" probe. ZAP confirmed this as a High-severity SQL Injection.

Write the fix (parameterized query / output encoding / capability check / whatever applies)
models.sequelize.query(
  "SELECT * FROM Products WHERE ((name LIKE :q OR description LIKE :q) AND deletedAt IS NULL) ORDER BY name",
  { replacements: { q: `%${criteria}%` } }
)

Why both tools caught it (1-2 sentences — what made this discoverable from both angles?)
Semgrep sees user input req.query.q flowing into a sink sequelize.query(...) via an unsafe template literal, which is exactly what the `express-sequelize-injection` rule matches on. ZAP sees the same defect from the outside because the unsanitised string is reflected verbatim into the SQL, so injecting a single quote produces an observable error/behaviour change in the response.
### Reflection (2-3 sentences)
Lecture 5 slide 15 calls this "the highest-confidence finding type." In a real PR review,
which of these two would you want first — the SAST finding or the DAST evidence — and why?
### Reflection (2-3 sentences)
Slide 15 frames it three ways: SAST alone = 'this could be a bug', DAST alone = 'this is a bug, but where?', andBoth = 'this is a bug, at this line, with this payload'. In a real PR review I would want the SAST finding first, because the DAST evidence on its own only tells me "this is a bug, but where?" - I would still have to grep the codebase to find the line, whereas the SAST hit pins `routes/search.ts:23` immediately. The DAST hit then upgrades the SAST signal from "this could be a bug" to "this is a bug, at this line, with this payload", which is exactly the "high-confidence finding" state the slide's diagram points at.
