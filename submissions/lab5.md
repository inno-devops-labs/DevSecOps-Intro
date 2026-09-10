# Lab 5 — SAST + DAST

## Task 1

### Baseline (unauthenticated)
Duration ~2–3 min. Exit line: `FAIL-NEW: 0 WARN-NEW: 8 PASS: 59`.

| riskcode | Level | Alert count |
|----------|-------|------------:|
| 2 | Medium | 2 |
| 1 | Low | 5 |
| 0 | Informational | 3 |

Highest risk in baseline: **Medium** (CSP missing, Cross-Domain Misconfiguration).

### Authenticated scan
Ran via `zap-auth.yaml` as `admin@juice-sh.op` / `admin123` on `lab5-net`. Active scan ~23 min (first run); report write may need re-check if `auth-report.json` missing on disk — re-run in progress / paste from `labs/lab5/results/` when present.

**Which run is “more serious”?** Baseline floods Low/Info header findings across many URLs; authenticated active scan reaches logged-in surfaces and can raise higher-impact alerts even if the raw alert *count* is lower. Report risk levels, not totals.

### Authenticated-only alerts (expected classes)
Examples that anonymous traffic cannot reach: admin-only APIs / basket / user profile under session — e.g. alerts on `/rest/admin/*` or authenticated `/api` after login cookie/JWT. Anonymous baseline never holds a valid session for those URLs.

### Pipeline note
Alert count is a bad comparison metric: passive baseline multiplies the same header issue by URL count; active auth concentrates on fewer, deeper findings. For a team lead, report **highest risk + new authenticated attack surface**, not “N alerts”. A pipeline that only runs `zap-baseline.py` on staging therefore **under-covers** broken access control and authz bugs.

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
`yaml.github-actions.security.run-shell-injection.run-shell-injection` on `.github/workflows/update-challenges-*.yml` — untrusted input into `run:` shells is a CI/CD attack path (Lecture 4 / OWASP Top 10 CI/CD).

### False positive
Many hits under `data/static/codefixes/` are deliberate teaching snippets, not production handlers — suppress by path for sprint triage (e.g. sequelize-injection in codefixes demos).

### One-rule fix this sprint
**`express-sequelize-injection`** — highest ERROR volume in app logic and maps directly to SQLi-class risk in login/search paths.

## Bonus

Correlate after `auth-report.json` is on disk, e.g. ZAP medium+ on an injectable parameter with Semgrep `express-sequelize-injection` / `hardcoded-jwt-secret` at a concrete `file:line` outside `codefixes/`.
