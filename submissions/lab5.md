# Lab 5 — SAST and DAST: Reading the Code, Then Watching It Run

Tooling: ZAP `ghcr.io/zaproxy/zaproxy:stable`, Semgrep 1.176.0, jq 1.6, on macOS 15.3.1 (arm64).
Target: `bkimminich/juice-shop:v20.0.0` on the `lab5-net` Docker network; source clone pinned to tag `v20.0.0`.

## Task 1

### 5.1 / 5.2 Alert counts and timing

| Risk level | Unauthenticated baseline | Authenticated full scan |
|---|---:|---:|
| High | 0 | **2** |
| Medium | 2 | 4 |
| Low | 5 | 3 |
| Informational | 3 | 4 |
| **Total** | **10** | **13** |
| Unique URLs with findings | 18 | 23 |
| Wall-clock time | **52 s** | **530 s (~8m50s)** |

Counts are from the report JSON via the provided `compare_zap.sh`. The baseline is passive (ZAP reads
traffic only); the authenticated run logs in as `admin@juice-sh.op`, spiders the authenticated surface,
then actively attacks it — hence the 10x runtime.

### Which run reported more, and which found the more serious ones

The authenticated run wins on **both** here (13 vs 10), but the total is the least interesting number.
The decisive difference is the **highest risk level**: the baseline's ceiling is Medium (missing CSP,
cross-domain misconfiguration — header hygiene), while the authenticated run surfaced **two High alerts
the baseline could not see at all: SQL Injection and a Vulnerable JS Library**. A scan that finds one
real SQL injection is more valuable than a scan that finds fifty missing headers, so "more serious" and
"more numerous" happen to agree this time only by luck. Read the top of each column, not the sum.

### Two alerts only the authenticated run found

1. **SQL Injection** — `http://juice-shop:3000/rest/products/search?q=%27%28` (CWE-89, High).
   The product-search endpoint is reachable anonymously, but ZAP's *active* scanner is what fires the
   injection payloads (`q='(`) and observes the 500; the passive baseline never mutates a request, so it
   cannot provoke or detect the fault. The alert is authenticated-only because it is *active*-only, not
   because the URL needs a session.

2. **Private IP Disclosure** — `http://juice-shop:3000/rest/admin/application-configuration`
   (Low/Medium). This is an admin configuration endpoint; the authenticated spider, carrying the admin
   session cookie, reached and crawled it, whereas the anonymous baseline was never handed the URL by the
   app and so never requested it. Here the gating really is authentication and crawl reach, not scan type.

   (A cleaner "needs a session cookie" example from the same run is **Session ID in URL Rewrite** on
   `/socket.io/?...&sid=...`: the `sid` only exists once a session has been established, so an anonymous
   pass has no such URL to flag.)

### Why "number of alerts" is a bad comparison — and the CI implication

The two totals are 10 and 13, which invites the conclusion that authentication added ~30% more risk.
That reading is wrong in both directions: the baseline's 10 are almost all passive header/caching
observations repeated across many URLs (five instances of "CSP not set", five "timestamp disclosure"),
while the authenticated run's smaller-looking column contains the only two findings anyone should lose
sleep over. Alert count conflates severity, instance-multiplicity and scan *type* into one meaningless
integer. To a team lead I would report the **highest-severity findings and their exploitability** — "one
confirmed SQL injection on `/rest/products/search`, one outdated front-end library, plus header hardening"
— not a headcount. The implication for a pipeline whose only DAST step is `zap-baseline.py` against
staging is stark: that step is passive, so it would have reported **zero High findings** and waved this
build through with a clean-looking 10-alert report while a live SQL injection shipped. A baseline scan is
a coverage floor, not a security gate; catching this class of bug needs an authenticated active scan (slow,
so nightly or pre-release, not per-commit) and SAST on the source, which is Task 2.

## Task 2

### 5.5 Severity split, rule table, error count

```console
$ jq '[.results[].extra.severity] | group_by(.) | map({severity: .[0], count: length})' semgrep.json
```

| Severity | Count |
|---|---:|
| ERROR | 13 |
| WARNING | 14 |
| **Total** | **27** |

```console
$ jq '.errors | length' semgrep.json
38
```

38 errors — partial parse failures and timeouts on individual files, expected for a large TypeScript
project and not invalidating the run (156 rules ran across 1000 targets, ~99.9% of lines parsed).

Top rules by finding count:

| n | Rule (short id) |
|---:|---|
| 6 | `sequelize-injection-express.express-sequelize-injection` |
| 5 | `github-actions.run-shell-injection` |
| 4 | `express-check-directory-listing` |
| 4 | `express-res-sendfile` |
| 4 | `github-actions-mutable-action-tag` |
| 1 | `express-open-redirect` |
| 1 | `jwt-hardcode.hardcoded-jwt-secret` |
| 1 | `code-string-concat` |
| 1 | `gha-curl-pipe-shell` |

Only 4 of the 27 findings are under `data/static/codefixes/` (the deliberately vulnerable teaching
snippets); the other 23 are in real application code (`routes/`, `lib/`, `server.ts`) or CI config.

### A workflow-file rule, and the Lecture 4 connection

`yaml.github-actions.security.run-shell-injection.run-shell-injection` fires 5 times, e.g.
`.github/workflows/update-challenges-www.yml:27`. The flagged step interpolates
`${{ github.ref_name }}` directly into a `run:` shell block. That is exactly the Lecture 4 CI/CD-security
lesson: GitHub-context values are attacker-influenceable (a branch or tag name can carry shell
metacharacters), and splicing them into a shell line is command injection *inside the runner*, which in a
`pull_request_target` or a workflow with a `BOT_TOKEN` in scope becomes token exfiltration — the same
`pull_request` vs `pull_request_target` distinction Lab 1's bonus workflow had to get right. The fix is
to pass the value through an `env:` variable and reference `"$REF_NAME"` quoted, never inline `${{ }}`.

### A finding I would suppress as a false positive

**File `routes/quarantineServer.ts:14`, rule `express-res-sendfile`** (WARNING):

```ts
export function serveQuarantineFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    if (!file.includes('/')) {
      res.sendFile(path.resolve('ftp/quarantine/', file))   // <-- line 14, flagged
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
```

The rule flags "user input in `res.sendFile`" as path traversal. Here it is a false positive *for this
specific code*, because the tainted value only reaches `sendFile` inside an `if (!file.includes('/'))`
guard: any path with a `/` — every `../` traversal sequence — takes the `else` branch and gets a 403.
Semgrep's taint tracking sees `params.file -> sendFile` and does not model that the intervening branch
condition makes traversal unreachable on the flagged line. (I would suppress *this* instance, not the
rule: the sibling `routes/keyServer.ts:14` is the same guarded pattern, but `routes/fileServer.ts` and
`routes/logfileServer.ts` are the genuinely vulnerable ones the rule is right about, so blanket-disabling
`express-res-sendfile` would hide real bugs.)

### One rule's worth of findings to fix this sprint

**`express-sequelize-injection`** — 6 findings, and it is the only SAST rule that points at the same
behaviour ZAP independently confirmed as a live High. Two of the six are in shipping request handlers
(`routes/search.ts:23`, `routes/login.ts:34`), both building a raw `models.sequelize.query()` string by
interpolating `req.query.q` / `req.body.email`. Fixing this rule closes an actively exploitable
authentication-bypass and data-exfiltration path — the highest real-world impact per unit of work on the
list — and the remedy is mechanical: replace string interpolation with Sequelize parameterised
replacements. Header findings can wait; a SQL injection reachable from an unauthenticated search box cannot.

## Bonus — one bug, two tools

| OWASP 2025 | ZAP alert (URL) | Semgrep rule (`file:line`) |
|---|---|---|
| A03 Injection | SQL Injection — `GET /rest/products/search?q='(` (HTTP 500) | `express-sequelize-injection` — `routes/search.ts:23` |
| A03 Injection | SQL Injection — `POST /rest/user/login` param `email` | `express-sequelize-injection` — `routes/login.ts:34` |

### Strongest row: SQL injection in product search

**Vulnerable source — `routes/search.ts:23`:**

```ts
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

`criteria` is `req.query.q`, truncated to 200 chars but otherwise concatenated straight into the SQL
string — the exact pattern Semgrep's `express-sequelize-injection` matches.

**The request ZAP used** (from `auth-report.json`, and reproduced by hand):

```console
$ curl -s "http://127.0.0.1:3000/rest/products/search?q=apple" -o /dev/null -w "%{http_code}\n"
200                         # benign query: valid SQL, returns products
$ curl -s "http://127.0.0.1:3000/rest/products/search?q=%27%28" -o /dev/null -w "%{http_code}\n"
500                         # q='(  -> unbalanced quote breaks the query -> Internal Server Error
```

ZAP's alert records `param: q`, `attack: '(`, `evidence: HTTP/1.1 500 Internal Server Error`. The single
quote closes the string literal early; the trailing `(` makes the surrounding SQL unparseable, and the
uncaught database error surfaces as a 500. A 500 on a crafted quote where a benign term returns 200 is the
signature of an unparameterised query — I confirmed exactly that transition rather than running a data
extraction, which the error-based signal already proves.

**The fix I would open a PR with** — parameterise instead of interpolate:

```ts
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :q OR description LIKE :q) AND deletedAt IS NULL) ORDER BY name',
  { replacements: { q: `%${criteria}%` }, type: models.sequelize.QueryTypes.SELECT }
)
```

Sequelize then binds `criteria` as a value, so a quote in the input is data, not syntax, and the 500 (and
the UNION-based data disclosure behind it) both close. The same change applies to the `email` interpolation
in `routes/login.ts:34`.

### Which finding goes first in the PR description

The **SQL injection**, unambiguously. Of everything both tools surfaced it is the only one that is
simultaneously (a) High severity, (b) reachable from an unauthenticated endpoint, (c) confirmed dynamically
by ZAP *and* statically by Semgrep, and (d) fixable in two lines. That convergence — a reviewer can read
the vulnerable line, see the request that trips it, and see the patch in one screen — is what makes it
lead the PR; the vulnerable JS library and the header findings are real but neither is exploitable to the
same effect nor as cheap to close.
