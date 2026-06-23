# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Spidered ~158 URLs; passive scan only
- Total alert types: 9 (41 instances)

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 2 |

### Authenticated full scan
- Spider 93 URLs + AJAX spider 588 URLs; active scan ~6 min
- Total alert types: 12 (37 instances)

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio by alert types: 12 / 9 ≈ 1.3×
- Ratio by instances: 37 / 41 ≈ 0.9×

My run did **not** reproduce the lecture's 10–20× figure, and it's worth being honest about why. The baseline run reports its alerts mostly against static assets (CSS/JS), which inflates its instance count, while the authenticated Automation-Framework scan in `zap-auth.yaml` explicitly excludes `.js/.css/.png/...` and concentrates on functional routes. So the authenticated scan produced *fewer but deeper* findings rather than a larger raw count. The qualitative gap is the real story: only the authenticated scan surfaced a **High-severity SQL Injection** plus session-handling issues, which the unauthenticated baseline cannot reach at all. The lecture's 10–20× holds when both scans actively attack the same surface; here the configs differ, so the count comparison understates while the severity comparison shows the true benefit.

### Two auth-only alerts
1. **SQL Injection (High)** — only the authenticated active scan found this. The unauthenticated baseline is passive (it never injects payloads) and most injectable endpoints (e.g. product search, login) require an authenticated session and active probing, so a passive anonymous pass simply never exercises them.
2. **Session ID in URL Rewrite (Medium)** — this concerns how the application carries a *logged-in user's* session identifier. With no login, the baseline scan never obtains a session to observe being rewritten into URLs, so the condition is invisible to it.

## Task 2: SAST with Semgrep

Scanned the pinned v20.0.0 source clone with `p/owasp-top-ten`, `p/javascript`, `p/secrets` (ERROR + WARNING).

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
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03 Injection (CI) |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A01 Broken Access Control |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01 / A05 |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A02 Cryptographic Failures |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03 |

### Triage shortcut (Lecture 5 slide 8)
I'd fix the **express-sequelize-injection** rule first. It's the highest-frequency finding (6 hits) and maps to a genuinely exploitable class — raw user input flowing into Sequelize queries, i.e. SQL injection. Unlike the CI shell-injection rule (which affects build pipelines, not the running app) or the header/listing findings (lower impact), this one is both frequent and directly reachable by an attacker, and a single fix pattern (parameterized queries / replacements) closes all six at once.

### False-positive sample
`data/static/codefixes/unionSqlInjectionChallenge_1.ts:6` — rule `express-sequelize-injection`. This file is a Juice Shop *challenge code-fix fixture*, not application code that ever runs in the served app — the `codefixes/` directory holds deliberately-vulnerable and patched snippets used by the training platform to teach fixes. Flagging it is technically correct (the snippet does concatenate input) but operationally a false positive: it isn't a live attack surface, so I'd suppress findings under `data/static/codefixes/` rather than treat them as real exposure.

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection (High) | /rest/products/search?q='( | express-sequelize-injection | routes/search.ts:23 | High (both agree) |
| 2 | A03 Injection | SQL Injection (High) | /rest/user/login | express-sequelize-injection | routes/login.ts:34 | High (both agree) |

### Strongest correlation deep-dive

**1. Vulnerable code (Semgrep — routes/search.ts:23)**

    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)

User input `req.query.q` flows unsanitized into a raw SQL string via template interpolation.

**2. Working payload (ZAP)**
- URI: `/rest/products/search?q='(`
- Attack string: `'(`
- Evidence: `HTTP/1.1 500 Internal Server Error` — the injected quote breaks SQL syntax, proving the input reaches the query engine. The known Juice Shop UNION exploit (`')) UNION SELECT ... FROM Users--`) extends this to dump the user table.

**3. The fix**
Use parameterized queries / bind replacements instead of string interpolation:

    models.sequelize.query(
      'SELECT * FROM Products WHERE ((name LIKE :term OR description LIKE :term) AND deletedAt IS NULL) ORDER BY name',
      { replacements: { term: `%${criteria}%` }, type: QueryTypes.SELECT }
    )

The user value is then bound as data, never parsed as SQL, so quotes and UNION clauses are treated literally.

**4. Why both tools caught it**
Semgrep saw it statically because the dangerous pattern is structurally obvious — tainted `req.query` reaching `sequelize.query()` through a template literal with no parameterization. ZAP saw it dynamically because that same unsanitized path turns a single injected quote into a 500 error at runtime. The static view explains *why* it's vulnerable (the code shape); the dynamic view proves *that* it's exploitable (a real payload triggers it) — which is exactly the static/dynamic complementarity.

### Reflection
This is "the highest-confidence finding type" (slide 15) because a static pattern alone can be a false positive and a dynamic 500 alone can have many causes — but together they corroborate each other. In a real PR review I'd want the **DAST evidence** first: a working payload against a live endpoint proves real, reachable impact and kills the "not exploitable in practice" objection, while the SAST finding then pinpoints the exact line to fix. Proof of exploitability sets priority; the static hit sets the patch location.