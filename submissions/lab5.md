# Lab 5 — SAST + DAST

## Task 1

### Baseline (unauthenticated)
Duration ~2–3 min. Exit line: `FAIL-NEW: 0 WARN-NEW: 8 PASS: 59`.

| riskcode | Level | Alert types |
|----------|-------|------------:|
| 2 | Medium | 2 |
| 1 | Low | 5 |
| 0 | Informational | 3 |

**Total alert types: 10.** Highest risk: **Medium** (CSP missing, Cross-Domain Misconfiguration). High: 0.

### Authenticated scan
`zap-auth-lean.yaml` as `admin@juice-sh.op` / `admin123` on `lab5-net`, `_JAVA_OPTIONS=-Xmx512m`.  
Timing: spider 18s + ajax 28s + passive 13s + activeScan **3:00** + report; plan **succeeded**, `auth-report.json` written.

| riskcode | Level | Alert types | Instance sum |
|----------|-------|------------:|-------------:|
| 3 | High | 2 | 3 |
| 2 | Medium | 4 | 18 |
| 1 | Low | 3 | 11 |
| 0 | Informational | 3 | 8 |

**Total alert types: 12.** Highest risk: **High** (SQL Injection, Vulnerable JS Library).

### Totals vs seriousness
Baseline reported **more Low/Info header noise** across many URLs (10 types, max Medium). Authenticated reported **slightly more types (12)** but found the **more serious** findings: **High** SQL Injection on login/search that baseline never reached as an active authenticated attack.

### Authenticated-only / auth-gated alerts
1. **SQL Injection** on `POST http://juice-shop:3000/rest/user/login` (param `email`, attack `'` → HTTP 500). Anonymous baseline is passive and never posts a session login with attacker-controlled `email`; without a valid auth context it does not exercise this active injection the same way.
2. **Authentication Request Identified** / session management on `http://juice-shop:3000/rest/user/login` and admin config paths such as `http://juice-shop:3000/rest/admin/application-configuration`. These appear because the AF user logged in as admin; an anonymous crawl has no Bearer/session for admin surfaces.

### Pipeline note
“Number of alerts” is a bad comparison: passive baseline multiplies the same missing-header issue by URL count, while authenticated active scan concentrates on fewer, deeper findings. For a team lead, report **highest risk level + newly reachable authenticated attack surface**, not raw totals. A pipeline whose only DAST step is `zap-baseline.py` on staging therefore **under-covers** broken access control and injection on authenticated APIs.

## Task 2

### Semgrep (`p/owasp-top-ten` + `p/javascript` + `p/secrets`) on `v20.0.0`

| Severity | Count |
|----------|------:|
| ERROR | 13 |
| WARNING | 14 |
| errors (parse) | 38 |

### Top rules
```
6	javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
5	yaml.github-actions.security.run-shell-injection.run-shell-injection
4	javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing
4	javascript.express.security.audit.express-res-sendfile.express-res-sendfile
4	yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag
```

### Workflow finding ↔ Lecture 4
`yaml.github-actions.security.run-shell-injection.run-shell-injection` on `.github/workflows/update-challenges-www.yml:27` (and siblings) — untrusted input interpolated into `run:` shells is a CI/CD attack path (Lecture 4 / OWASP Top 10 for CI/CD).

### False positive
**Rule:** `express-sequelize-injection`  
**File:** `data/static/codefixes/dbSchemaChallenge_1.ts:5`  
This path is a **teaching snippet** under `codefixes/`, not a live Express route. Suppressing by path (`codefixes/`) for sprint triage is correct; fixing it would not change the running app.

### One-rule fix this sprint
**`express-sequelize-injection`** on real routes (`routes/login.ts`, `routes/search.ts`) — highest ERROR volume in application logic and maps directly to the High SQLi ZAP found.

## Bonus

| OWASP | ZAP alert + URL | Semgrep rule + file:line |
|-------|-----------------|--------------------------|
| A03 Injection (2021) / A05 (2025) | SQL Injection — `POST http://juice-shop:3000/rest/user/login` (param `email`, attack `'`) | `express-sequelize-injection` → `routes/login.ts:34` |
| A03 Injection | SQL Injection — `GET http://juice-shop:3000/rest/products/search?q=%27%28` | `express-sequelize-injection` → `routes/search.ts:23` |

### Strongest row (login)
Vulnerable source (`routes/login.ts:34`):
```ts
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```
ZAP request: `POST /rest/user/login` with JSON body field `email` set to `'` → HTTP 500 (evidence of unsafely interpolated SQL).

**Fix:** parameterized Sequelize query, e.g.
```ts
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  { replacements: { email: req.body.email || '', password: security.hash(req.body.password || '') }, model: UserModel, plain: true }
)
```

Put **login SQLi** first in the PR description: both tools independently confirm it, risk is High, and it sits on the authentication boundary.
