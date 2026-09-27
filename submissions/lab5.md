# Lab 5 — SAST and DAST on Juice Shop v20.0.0

Target: `bkimminich/juice-shop:v20.0.0`, run on the `lab5-net` Docker network as host `juice-shop`.
Tools: ZAP `ghcr.io/zaproxy/zaproxy:stable`, Semgrep `1.176.0`. All numbers below are taken from the JSON reports, not the console summaries.

## Task 1

### Alert counts by risk level and run time

Counts are of distinct alert types per run (as reported in each `site[].alerts[]`), grouped by `riskcode`.

| Risk level | Unauthenticated baseline | Authenticated (`zap-auth.yaml`) | Authenticated, hardened (`zap-auth-fixed.yaml`) |
|---|---|---|---|
| High (3) | 0 | 2 | 2 |
| Medium (2) | 2 | 4 | 9 |
| Low (1) | 5 | 3 | 3 |
| Informational (0) | 3 | 4 | 4 |
| **Total alert types** | **10** | **13** | **18** |
| Wall-clock time | ~85 s (≈1.5 min) | ~447 s (≈7.5 min) | ~480 s (≈8 min) |

Why three runs: the provided `zap-auth.yaml` logs in and actively scans, but its spider only follows links an anonymous crawl exposes, and this build hands the JWT back in the login JSON body rather than only as a cookie. I kept the provided run for transparency and added a hardened config (`scripts/zap-auth-fixed.yaml`) that (a) carries the token as both an `Authorization: Bearer` header and a `token` cookie via `sessionManagement: headers`, and (b) uses a `requestor` job to seed the authenticated-only REST endpoints the SPA calls after login (`/profile`, `/api/Users`, `/rest/basket/1`, `/api/Cards`, …). That is what lifted Medium from 4 to 9 — the extra alerts are on genuinely authenticated surface.

### Which run reported more, and which found the more serious ones

The **hardened authenticated run reported the most alerts in total (18 vs 13 vs 10)**. On *seriousness*, look at the highest risk level in each: the **baseline tops out at Medium (0 High)**, while **both authenticated runs reach High** — `SQL Injection` (plugin 40018) and `Vulnerable JS Library` (plugin 10003, Angular 21.2.12, CVE-2026-52725 / -50557 / -54267). So the baseline is both smaller *and* strictly less severe: passive scanning never fires an attack payload, so it structurally cannot surface an active-only finding like SQL injection.

### Two alerts only the authenticated run found, with URLs and reachability reason

Both are from the hardened authenticated run and are genuinely unreachable anonymously (verified by hand — an anonymous `GET /profile` returns `HTTP 500 "Blocked illegal activity"`, while the same request with a valid `token` cookie returns `HTTP 200` with the form and CSP header):

1. **Absence of Anti-CSRF Tokens** — `GET http://juice-shop:3000/profile` (plugin 10202, CWE-352). `/profile` is a server-rendered account page whose email/username change form (`<form action="./profile" method="post">`) is only emitted to a request carrying a valid session. An anonymous request is rejected before the HTML is produced, so a passive/anonymous scan never sees the form and cannot flag its missing CSRF token.
2. **CSP: script-src unsafe-eval** — `GET http://juice-shop:3000/profile` (plugin 10055). The `Content-Security-Policy: … script-src 'self' 'unsafe-eval'` header is only sent on the authenticated `/profile` response. With no authenticated response to parse, an anonymous scan has no CSP to evaluate on this path.

### Why "number of alerts" is a bad comparison, and what to report instead

The totals rank hardened-auth (18) > auth (13) > baseline (10), yet the baseline is the *weakest* scan — it found zero High-risk issues because it never attacks, and much of its count is per-URL header/caching noise (`Timestamp Disclosure`, `X-Content-Type-Options`) repeated across every page it happened to crawl. A single number blends noisy passive observations with real exploitable bugs and is trivially inflated just by crawling more URLs. To a team lead I would report **counts bucketed by severity, plus what the top findings actually are** — e.g. "2 High (SQL injection on `/rest/user/login` and a vulnerable Angular version), then CSP/anti-CSRF gaps" — because that maps to risk and remediation effort, not crawl breadth. The implication for a pipeline whose only DAST step is `zap-baseline.py` against staging is stark: a passive baseline **cannot find injection, auth, or business-logic flaws** and only ever sees the anonymous surface, so it would have missed both High findings here. It is a useful header/config guardrail, not a security gate — an authenticated active scan (or targeted DAST) has to run somewhere before release.

## Task 2

### Severity split, rule table, error count (Semgrep 1.176.0)

Config: `--config=p/owasp-top-ten --config=p/javascript --config=p/secrets --severity ERROR --severity WARNING`. 27 findings total.

Severity split:

| Severity | Count |
|---|---|
| ERROR | 13 |
| WARNING | 14 |

Top rules by count:

| n | Rule |
|---|---|
| 6 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| 5 | `yaml.github-actions.security.run-shell-injection.run-shell-injection` |
| 4 | `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` |
| 4 | `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` |
| 4 | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` |
| 1 | `javascript.express.security.audit.express-open-redirect.express-open-redirect` |
| 1 | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` |
| 1 | `javascript.lang.security.audit.code-string-concat.code-string-concat` |
| 1 | `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` |

**Error count: 44** (16 syntax errors, 5 timeouts, 23 partial-parse errors — mostly on `.ts` teaching snippets under `data/static/codefixes/`, Angular HTML templates, and the `Dockerfile`). As the lab notes, these are expected and do not invalidate the run.

### A workflow-file rule and its link to Lecture 4

`yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` fires on `.github/workflows/codeql-analysis.yml:23/34/36` (`github/codeql-action/init@v3`, `analyze@v3`) and `ci.yml:202` (`coverallsapp/github-action@v2`). These `uses:` pin an action to a **mutable tag** rather than a 40-char commit SHA. This is exactly Lecture 4's hardening rule "Pin actions by SHA (not tag)" (Slide 7/8, CICD-SEC-3/8) and its case study of the **March 2025 `tj-actions/changed-files` compromise**, where every tag `v1…v45.0.7` was re-pointed at one malicious commit — anyone on a tag ran it, anyone pinned to a SHA did not. (The related `gha-curl-pipe-shell` finding at `ci.yml:372`, `curl … | sh` for the Heroku CLI, maps to the same lecture's Codecov bash-uploader case, Slide 14.)

### One finding I would suppress as a false positive

**File `routes/quarantineServer.ts`, line 14, rule `javascript.express.security.audit.express-res-sendfile.express-res-sendfile`.**

```ts
export function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    if (!file.includes('/')) {
      res.sendFile(path.resolve('ftp/quarantine/', file))   // line 14 — flagged
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
```

The rule warns that a user-controlled value reaches `res.sendFile`, implying path traversal. Here it is wrong *for this specific code*: the `sendFile` is guarded by `if (!file.includes('/'))`, and Express has already percent-decoded the route param before the handler runs, so an encoded slash (`%2f`) is decoded to `/` and caught by the same guard. Without a `/` or `\`, `path.resolve('ftp/quarantine/', file)` cannot climb out of the quarantine directory. I confirmed this dynamically: `/ftp/quarantine/..%2Fpackage.json.bak`, `%2e%2e%2f%2e%2e%2fpackage.json`, and `..%5c..%5cpackage.json` all return **403**, while a legitimate `juicy_malware_linux_amd_64.url` returns 200. The traversal the rule assumes is not reachable, so this instance is a false positive. (Note: the *sibling* `routes/fileServer.ts:33` is a real bug — it applies `cutOffPoisonNullByte`, i.e. it deliberately allows a poison-null-byte bypass — so I would keep that one.)

### If I could fix exactly one rule's worth of findings this sprint

**`express-sequelize-injection`** (6 findings; in application code: `routes/search.ts:23`, `routes/login.ts:34`). It is the highest-impact rule in the set: both instances are raw string interpolation into `models.sequelize.query(...)`, both are confirmed exploitable by ZAP (plugin 40018), and the `login.ts` one is an unauthenticated SQL-injection auth bypass leading to admin takeover. The fix is mechanical and self-contained — parameterized queries (bind replacements) or Sequelize model finders — so it is a high-value, low-risk sprint item.

## Bonus — One bug, two tools

| OWASP category | ZAP alert & URL | Semgrep rule & file:line |
|---|---|---|
| A03:2021 / 2025 — Injection | `SQL Injection` (plugin 40018) — `POST http://juice-shop:3000/rest/user/login` (param `email`) and `GET /rest/products/search?q=` | `express-sequelize-injection` — `routes/login.ts:34`, `routes/search.ts:23` |
| A05 — Security Misconfiguration | `Absence of Anti-CSRF Tokens` (plugin 10202) — `GET /profile` | `code-string-concat` / open-redirect family (adjacent), correlated via the authenticated profile surface |

### Strongest row: SQL injection on `/rest/user/login`

**Vulnerable source (`routes/login.ts:34`):**

```ts
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

The `email` field is concatenated straight into the SQL string. Semgrep's `express-sequelize-injection` flags this line statically; ZAP's active scanner independently confirms it dynamically.

**Request ZAP used:** `POST /rest/user/login` with the `email` parameter carrying a single-quote-based SQL breakout payload (ZAP's `40018` injection probe on `param=email`), and the same rule on `GET /rest/products/search?q=` (`routes/search.ts:23`). ZAP marks the login case High-risk (CWE-89). The classic manual equivalent closes the `email` string and comments out the password check, logging in as the first user (admin) with no password.

**Fix I would open a PR with:** stop building SQL by concatenation. Use a parameterized query with bind replacements, e.g.

```ts
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  { replacements: { email: req.body.email ?? '', password: security.hash(req.body.password ?? '') },
    model: UserModel, plain: true }
)
```

or, better, replace the raw query with `UserModel.findOne({ where: { email, password: hashed } })`, and apply the same pattern to `routes/search.ts:23`.

### Which finding goes first in the PR description, and why

The **login SQL injection** goes first. It is the single most severe issue found: it is reachable **unauthenticated**, both tools agree on it independently (so it is not a tool artifact), and it yields a full authentication bypass to the admin account — the worst possible outcome for an auth endpoint. Everything else (CSP, anti-CSRF, header hygiene) is defense-in-depth by comparison, so it belongs after the injection fix in both the PR and the remediation order.
