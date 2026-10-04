# Lab 5 — SAST and DAST: Reading the Code, Then Watching It Run

## Task 1

### 1. Setup

`bkimminich/juice-shop:v20.0.0` was run on a dedicated `lab5-net` Docker network. Two ZAP runs were made against it with `ghcr.io/zaproxy/zaproxy:stable`:

- **Unauthenticated baseline** — `zap-baseline.py` (passive spider + passive scan only).
- **Authenticated full scan** — `zap.sh -cmd -autorun labs/lab5/scripts/zap-auth.yaml` (logs in as `admin@juice-sh.op`, spiders with a real browser via `spiderAjax`, then runs the active scanner).

### 2. Alert counts by risk level

| Risk          | Baseline (alert types / instances) | Authenticated (alert types / instances) |
| ------------- | ----------------------------------: | ---------------------------------------: |
| High          |                                0 / 0 |                                    2 / 3 |
| Medium        |                                2 / 7 |                                   4 / 18 |
| Low           |                               5 / 21 |                                   3 / 11 |
| Informational |                               2 / 10 |                                   4 / 11 |
| **Total**     |                          **9 / 38**  |                             **13 / 43**  |

Counts are taken directly from `baseline-report.json` and `auth-report.json` (`riskdesc` and `instances[]` per alert), which is also what `labs/lab5/scripts/compare_zap.sh` reports for alert-type totals (9 vs 13).

**Duration:**

| Run                              |            Time taken |
| -------------------------------- | ---------------------: |
| Unauthenticated baseline         |            ~96 s (1m36s) |
| Authenticated (full automation)  |          ~387 s (6m27s) |
| — of which: spider               |                    18 s |
| — of which: spiderAjax           |                    54 s |
| — of which: active scan          |                  4m 57s |

### 3. Which run reported more, and which found the more serious issues?

The **authenticated run** reported more alerts by both measures: 13 alert types (43 instances) vs. 9 (38), *and* it reached a higher maximum risk level — two **High**-risk alerts (SQL Injection, Vulnerable JS Library) against a baseline whose worst finding was **Medium** (CSP header missing, Cross-Domain Misconfiguration). In this run the two metrics happen to agree, but they measure different things: the baseline is a passive-only crawl that only ever flags header/caching hygiene issues on every URL it can see without JavaScript, while the authenticated run adds an active scanner that actually attacks a smaller, logged-in surface — which is why the lab's own pitfalls note that the authenticated run can come out *lower* in total count while still finding the worse bugs. Here it didn't come out lower, but the reason it's ahead is the active attack phase, not "it saw more URLs."

### 4. Two alerts only the authenticated run found

- **SQL Injection** — `POST http://juice-shop:3000/rest/user/login` (param `email`, attack `'`). The plain baseline spider never executes the Angular SPA's JavaScript, so it never submits the login form's XHR request in the first place; only the authenticated job's `spiderAjax` stage (a real, JS-executing browser) drives that POST, which the subsequent active-scan phase then fuzzes. An anonymous *crawl* — as opposed to an anonymous *request*, which would in fact reach this public endpoint — never generates the request for the scanner to attack.
- **Vulnerable JS Library** — `http://juice-shop:3000/chunk-GJJPXCX3.js`. This is an Angular lazy-loaded route chunk that the browser only fetches once it navigates past a client-side auth guard to a logged-in page; an anonymous session is redirected before that route (and its chunk) is ever requested, so the baseline's crawl never pulls this file down to inspect its bundled library versions.

### 5. Why "number of alerts" is a bad comparison metric

A raw alert count conflates nine passive header-hygiene warnings with two active, exploitable findings — the authenticated run "wins" on count here, but it would win just as convincingly on a run that found five High-risk bugs and one Low, versus a baseline that found forty Informational ones on cacheable-content headers. What matters is the **highest risk level reached** and, more specifically, the **alert type and CWE** (SQL Injection / CWE-89 is a different order of problem than a missing CSP header), not how many URLs happened to trip the same low-severity rule. To a team lead I would report the risk-level breakdown and name the two High-risk findings explicitly, not "13 alerts vs 9." The implication for a pipeline whose only DAST step is `zap-baseline.py` against staging is that it will never catch this class of bug at all: baseline is passive by design, so a real SQL injection like the one above would sail through CI green every time, giving false confidence that the app was "DAST-tested" when only its response headers were.

## Task 2

### 1. Semgrep run

```bash
semgrep --config=p/owasp-top-ten --config=p/javascript --config=p/secrets \
  --severity ERROR --severity WARNING \
  --json -o labs/lab5/results/semgrep.json \
  labs/lab5/semgrep/juice-shop
```

Semgrep 1.178.0, against the source cloned at tag `v20.0.0`. 156 rules ran across 1000 tracked files (~99.9% parsed) in about 27 seconds.

**Severity split:**

| Severity | Count |
| -------- | ----: |
| ERROR    |    13 |
| WARNING  |    14 |
| **Total**|  **27** |

**Rule table (all rules that fired):**

| n | Rule |
| -: | ---- |
| 6 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| 5 | `yaml.github-actions.security.run-shell-injection.run-shell-injection` |
| 4 | `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` |
| 4 | `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` |
| 4 | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` |
| 1 | `javascript.express.security.audit.express-open-redirect.express-open-redirect` |
| 1 | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` |
| 1 | `javascript.lang.security.audit.code-string-concat.code-string-concat` |
| 1 | `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` |

**Errors:** `.errors | length` → **42** (parse timeouts/syntax issues on some files — expected and does not invalidate the run).

Of the 27 findings, 4 sit under `data/static/codefixes/` (the deliberately-vulnerable teaching snippets for `dbSchemaChallenge`/`unionSqlInjectionChallenge`) and were excluded from the analysis below; the remaining 23 are in real application code and workflow files.

### 2. A workflow-file rule, connected to Lecture 4

`yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` fires on `.github/workflows/ci.yml:372`:

```yaml
- name: "Install Heroku CLI"
  run: curl https://cli-assets.heroku.com/install.sh | sh
```

This is the exact pattern Lecture 4 uses as its supply-chain example: the April 2021 Codecov incident, where attackers modified the `bash` uploader script that "thousands of CI pipelines" fetched via `curl | bash <latest>`, letting them exfiltrate secrets from every pipeline that ran it. Lecture 4's fix for that slide is "pin by hash instead of `curl | bash <latest>`" — the same remediation applies here: `install.sh` is fetched unpinned, over plain HTTPS with no checksum or hash pin, and piped straight into a shell running with the workflow's full permissions and secrets. A compromised or MITM'd copy of that script would run with the same blast radius as the Codecov uploader did.

### 3. A false positive

**`routes/keyServer.ts:14`, rule `javascript.express.security.audit.express-res-sendfile.express-res-sendfile`:**

```ts
export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    if (!file.includes('/')) {
      res.sendFile(path.resolve('encryptionkeys/', file))   // <- flagged line
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
```

The rule's generic concern is path traversal via `res.sendFile` on an unvalidated parameter. Here, though, `file` has already been rejected if it contains a `/`, and Express decodes the route parameter exactly once before this handler ever sees it — so a traversal payload like `..%2f..%2fetc%2fpasswd` decodes to a string containing a literal `/` and is rejected by the guard, and a *double*-encoded `..%252f..` decodes only as far as the literal characters `%2f` (no real slash), which `path.resolve` treats as part of a single filename, not a directory separator. The one payload that slips past the guard, a bare `..`, resolves to the parent of `encryptionkeys/` — a directory, not a file — which `res.sendFile` refuses to serve (`EISDIR`) rather than listing its contents. There is no encoding or traversal depth that both avoids a literal `/` and escapes more than one directory level, so the specific vulnerability this rule warns about does not exist in this handler; I would suppress it here (though not for `fileServer.ts`, which serves attacker-influenced filenames with only an extension allowlist and no such rejection).

### 4. One rule to fix this sprint

`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` (2 real findings: `routes/login.ts:34`, `routes/search.ts:23`). It's the only Semgrep finding in application code that ZAP's authenticated scan *independently confirmed* is exploitable (see Bonus below) — a real SQL injection outranks every header/config finding on this list, both endpoints are two-line fixes (swap string interpolation for Sequelize `replacements`), and one of the two is an authentication query, so the fix also closes an auth-bypass path, not just an information leak.

## Bonus — One bug, two tools

| OWASP category | ZAP alert & URL | Semgrep rule & `file:line` |
| --------------- | ---------------- | ---------------------------- |
| A03:2021/2025 – Injection (SQL Injection, CWE-89) | SQL Injection — `GET /rest/products/search?q=%27%28` (param `q`, attack `'(`) | `express-sequelize-injection` — `routes/search.ts:23` |
| A03:2021/2025 – Injection (SQL Injection, CWE-89) | SQL Injection — `POST /rest/user/login` (param `email`, attack `'`) | `express-sequelize-injection` — `routes/login.ts:34` |

### Strongest row: the login SQL injection

**Vulnerable source** (`routes/login.ts:34`):

```ts
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

**Request ZAP used:** ZAP's active scanner replayed the JSON login POST it had captured during the authenticated `spiderAjax` crawl, substituting a single quote for the `email` field:

```
POST /rest/user/login HTTP/1.1
Host: juice-shop:3000
Content-Type: application/json

{"email":"'","password":"<hash captured from the credentials submitted during the spiderAjax login>"}
```

That single quote breaks out of the string literal in the interpolated query, produced an `HTTP/1.1 500 Internal Server Error` (ZAP's evidence for the alert), and confirms the same injection point the classic Juice Shop bypass abuses in full (`' or 1=1--` as the email, with the trailing `AND password = '...'` commented out) to log in as `admin@juice-sh.op` without a password.

**Fix:**

```ts
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  { replacements: { email: req.body.email || '', password: security.hash(req.body.password || '') }, model: UserModel, plain: true }
)
```

Named replacements let Sequelize bind the values as parameters instead of splicing them into the SQL text, which removes the injection point entirely without changing the query's behavior for legitimate input. The same fix pattern (`replacements` with `:criteria`) applies to `routes/search.ts:23`.

I would put the **login** finding first in the PR description: `search.ts` leaks data via a `LIKE` clause, but `login.ts` is a direct authentication-bypass path — the same query pattern grants full account takeover of any user, including the admin account, with no credentials at all, which is a materially different severity than an information-disclosure bug in a product search box.
