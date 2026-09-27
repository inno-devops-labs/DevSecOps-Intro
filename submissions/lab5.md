# Lab 5 — SAST and DAST

**Environment**
- Windows 11 host, Docker Desktop 29.7.2. Docker VM memory raised to 4 GiB for this lab: with the default 2 GiB the authenticated scan's report job ran the JVM out of heap and hung after the active scan finished.
- ZAP `ghcr.io/zaproxy/zaproxy:stable` = **2.17.0**. Semgrep **1.176.1**. Target `bkimminich/juice-shop:v20.0.0` on `127.0.0.1:3000`, source cloned at tag `v20.0.0`.
- Both scans ran on the `lab5-net` Docker network against the hostname `juice-shop`.

## Task 1

### 5.1 / 5.2 Counts by risk level

Counts are **alert types** (distinct rules) with **instance totals** in brackets, taken from each report's `.site[].alerts[]` (`riskcode` 3=High, 2=Medium, 1=Low, 0=Info; `count` is instances).

| Risk | Unauthenticated baseline | Authenticated full scan |
|---|---|---|
| High | 0 | **2** (21) |
| Medium | 2 (7) | 4 (18) |
| Low | 5 (17) | 3 (11) |
| Info | 3 (11) | 4 (11) |
| **Total types (instances)** | **10 (39)** | **13 (43)** |

- Baseline: **~86 s**, exit code 2 (non-zero because it found warnings — expected). Passive only, 158 URLs seen.
- Authenticated: **~25 min** wall clock — spider 18 s, AJAX spider ~7 min (93→110 URLs), active scan 10.5 min (capped by `maxScanDurationInMins: 10`), report generation ~6 min.

High alerts, authenticated run: **SQL Injection** (`40018`, 2 instances) and **Vulnerable JS Library** (`10003`, 1).

### 5.3 Compare

**Which run reported more, and which found the more serious?** The authenticated run reported more on both counts — 13 alert types / 43 instances vs 10 / 39 — *and* it found the more serious ones. The baseline's highest risk level is **Medium**; the authenticated run reaches **High** (SQL Injection, Vulnerable JS Library). The two extra numbers are small, but the severity gap is the whole story.

**Two alerts only the authenticated run found, with URLs and why the anonymous baseline missed them:**

1. **SQL Injection** — `GET http://juice-shop:3000/rest/products/search?q='(` and `POST http://juice-shop:3000/rest/user/login` (param `email`). Both endpoints are *reachable* anonymously; the baseline missed them because it is **passive** and never sends an attack payload — only the active scan the authenticated run adds injects the `'` that trips the bug.
2. **Session ID in URL Rewrite** — `GET http://juice-shop:3000/socket.io/?EIO=4&transport=polling&sid=…`. This URL only exists after a live Socket.IO session is negotiated by the authenticated AJAX/SPA spider; the baseline's plain unauthenticated spider never drives that handshake, so no `sid`-bearing URL is ever observed.

Honest note: the difference between the two runs here is driven mainly by **active-vs-passive scanning and the AJAX spider**, and only partly by authentication — Juice Shop exposes most of its surface without login.

**Why "number of alerts" is a bad comparison, and what to report instead.** The counts are almost equal (10 vs 13) yet one run found nothing above Medium and the other found exploitable SQL injection — the totals hide the only fact that matters. Worse, a passive baseline inflates its total with per-URL header/caching findings repeated across every page, so a scan can *lose* alerts while gaining real risk. To a team lead I'd report **highest severity and the specific exploitable findings** (here: confirmed SQLi, with the request), not a headline number. That means a pipeline whose only DAST step is `zap-baseline.py` against staging will pass while missing every injection and auth-logic bug, because it never attacks — the baseline is a coverage floor, not a security gate.

## Task 2

### 5.5 Results

Semgrep 1.176.1, `p/owasp-top-ten` + `p/javascript` + `p/secrets`, `--severity ERROR --severity WARNING`. **27 findings**, **42 errors** (16 syntax errors + 3 timeouts on `frontend/src/assets/private/three.js` + 23 partial-parse warnings on `.html`/`.ts`/YAML/Dockerfile — all expected, none invalidate the run).

Severity split: **ERROR 13, WARNING 14**.

| n | rule |
|---|---|
| 6 | `express-sequelize-injection` |
| 5 | `run-shell-injection` (github-actions) |
| 4 | `express-check-directory-listing` |
| 4 | `express-res-sendfile` |
| 4 | `github-actions-mutable-action-tag` |
| 1 | `express-open-redirect` |
| 1 | `hardcoded-jwt-secret` |
| 1 | `code-string-concat` |
| 1 | `gha-curl-pipe-shell` |

**A `.github/workflows/` rule, connected to Lecture 4.** `github-actions-mutable-action-tag` fires on `.github/workflows/codeql-analysis.yml:23` for `uses: github/codeql-action/init@v3` (and `autobuild@v3`, `analyze@v3`, and `coverallsapp/github-action@v2` in `ci.yml:202`). A `@v3` tag is mutable — the action owner (or an attacker who compromises them) can silently repoint it to malicious code that then runs with the workflow's secrets. This is the same **software-supply-chain / dependency-integrity** problem Lab 4 (SCA/SBOM) was about, pushed up into CI: a pinned dependency graph is worthless if the pipeline pulls actions by a moving tag. Fix: pin third-party actions to a full commit SHA (as Juice Shop already does for `actions/checkout`).

**One finding I'd suppress as a false positive.** `express-res-sendfile` at **`routes/logfileServer.ts:14`** — `res.sendFile(path.resolve('logs/', file))`. The rule assumes `file` is attacker-controlled and enables path traversal, but **line 13 rejects any `file` containing `/`** (`if (!file.includes('/'))`), so `../` traversal is impossible, and on the Linux container target `\` is an ordinary filename character, not a separator. The only reachable files are non-recursive entries directly under `logs/`. The rule flags the sink without seeing the guard. (For contrast, the *true* traversal risk lives in `routes/fileServer.ts:33`, which passes the filename through allow-listing and `cutOffPoisonNullByte` — a deliberately weaker, bypassable path.)

**One rule's worth of findings to fix this sprint:** `express-sequelize-injection` (6 findings, 4 in real app code: `routes/search.ts`, `routes/login.ts`, plus the codefix snippets). It is the highest-impact rule, it is the one ZAP independently confirmed as a **High** finding, and SQL injection over the product search and login queries is directly exploitable for data theft and auth bypass. Everything else on the list is header hygiene or CI hardening by comparison.

## Bonus — One bug, two tools

| OWASP (2025) | ZAP alert & URL | Semgrep rule & `file:line` |
|---|---|---|
| A03 Injection | SQL Injection — `GET /rest/products/search?q='(` | `express-sequelize-injection` — `routes/search.ts:23` |
| A03 Injection | SQL Injection — `POST /rest/user/login` (param `email`) | `express-sequelize-injection` — `routes/login.ts:34` |

**Strongest row — product search SQL injection.**

Vulnerable source, `routes/search.ts:20-23`:
```ts
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```
`req.query.q` is interpolated straight into the SQL string — no parameterisation, no escaping. The only limit is a 200-char truncation.

Request ZAP used (reproduced against the running app):
```
GET /rest/products/search?q=%27%28   →   q = '(
```
Response: `HTTP 500` with `Error: SQLITE_ERROR: near "(": syntax error` — the injected `'` closes the string literal and `(` reaches the parser, proving the input lands in raw SQL. This is the entry point for the union-based injection that dumps the `Users` table (email + password hash).

Fix I'd open a PR with — bind the value instead of interpolating it:
```ts
models.sequelize.query(
  "SELECT * FROM Products WHERE ((name LIKE :q OR description LIKE :q) AND deletedAt IS NULL) ORDER BY name",
  { replacements: { q: `%${criteria}%` }, type: QueryTypes.SELECT }
)
```

**Which finding goes first in the PR description:** the product-search SQLi. It needs no authentication, both tools point at the same line independently (SAST sink + DAST confirmed exploit), and it leaks credentials — so it is both the most severe and the easiest for a reviewer to reproduce from the one-line request above.
