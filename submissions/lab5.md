# Lab 5 — Submission

DAST with ZAP (unauthenticated + authenticated) and SAST with Semgrep on
`bkimminich/juice-shop:v20.0.0`, then one bug both tools reach.

## Setup

```console
$ semgrep --version
1.176.1
$ git -C labs/lab5/semgrep/juice-shop describe --tags
v20.0.0
```

ZAP image: `ghcr.io/zaproxy/zaproxy:stable`. Target ran as container `juice-shop` on the
`lab5-net` Docker network, so both scans reached it as `http://juice-shop:3000`. The Semgrep
clone is pinned to `v20.0.0` — the same tag the containers run — so a source line can be tied
to a live request without the version drift the lab warns about.

## Task 1 — ZAP baseline vs authenticated

Durations are the real container lifetimes from `docker events`, not estimates:

| Run | Type | Duration | Alerts | High | Medium | Low | Info |
|---|---|---:|---:|---:|---:|---:|---:|
| `zap-baseline.py` | passive, anonymous | **57 s** | 10 | 0 | 2 | 5 | 3 |
| Automation Framework (`zap-auth.yaml`) | active, logged in | **5 min 54 s** | 13 | **2** | 4 | 3 | 4 |

Counts are `riskcode` from each report's JSON (`3=High, 2=Medium, 1=Low, 0=Info`).

### Which run reported more, and which found the more serious ones?

The authenticated run found **more in total** (13 vs 10) **and the more serious ones**. The
baseline's highest risk level is Medium; the authenticated run is the only one with **High**
alerts — SQL Injection and a Vulnerable JS Library. So on this pair the two questions happen to
agree, but they are different questions: the count went up by three while the *severity ceiling*
jumped from Medium to High.

### Two alerts only the authenticated run reported

The lab asks for two auth-only alerts and why an anonymous request "could not reach them." I
checked, and the honest answer is that **it could** — so I am reporting what the difference
actually is rather than inventing an authorization story:

| Alert (auth-only) | URL | Anonymous reachability — tested |
|---|---|---|
| **SQL Injection** (High) | `GET /rest/products/search?q=%27%28` | Reachable without a login: `curl` of that URL returns `500 SQLITE_ERROR near "("`. |
| **Private IP Disclosure** (Low) | `GET /rest/admin/application-configuration` | Reachable without a login: returns `200` and leaks `192.168.99.100:3000` in the body. |

Neither endpoint is gated behind the session. The reason they appear *only* in the second run is
the **scan type, not the credentials**:

- `zap-baseline.py` is **passive** — it never sends the `'(` payload, so it can never provoke the
  500 that reveals the injection. The active scan does, which is the whole High-severity delta.
- The authenticated config also adds an **AJAX spider** and drives the login flow, so it crawls
  `socket.io` and `/rest/admin/...` endpoints the one-minute passive spider never visited. More
  surface crawled, more passive alerts fired.

So "authenticated" is doing less work here than "active + deeper crawl." The login matters for
challenges that truly need a session; for this alert set it mostly changed *how hard ZAP looked*.

### Why "number of alerts" is a bad comparison

The two totals (10 vs 13) are three apart, but they are not measuring the same thing: the baseline
inflates its count with per-URL passive header/caching warnings (five identical CSP rows, one per
page it happened to see), while the active run spends its count on two genuine High findings. A run
can lower its total simply by crawling fewer URLs and still be the more dangerous result — which is
exactly the lab's warning that the authenticated run can report *fewer* alerts. To a team lead I
would report **the highest severity present and the count of distinct High/Medium rule types**
(here: SQLi and a vulnerable Angular library), not the raw alert number. For a pipeline whose only
DAST step is `zap-baseline.py` against staging, the implication is blunt: it is passive, so it will
**never** find the SQL injection — the one thing on this page you would actually page someone for.
Baseline is a fast headers-and-hygiene gate, not a vulnerability scanner, and should not be sold as
one.

## Task 2 — Semgrep SAST

```console
$ semgrep --config=p/owasp-top-ten --config=p/javascript --config=p/secrets \
    --severity ERROR --severity WARNING \
    --json -o labs/lab5/results/semgrep.json \
    labs/lab5/semgrep/juice-shop
```

### Severity split, top rules, error count

```console
$ jq '[.results[].extra.severity] | group_by(.) | map({severity: .[0], count: length})' …
[ { "severity": "ERROR", "count": 13 }, { "severity": "WARNING", "count": 14 } ]

$ jq '.errors | length' …
41
```

27 findings total. Rules ranked by hit count:

| n | Rule | Where |
|---:|---|---|
| 6 | `express-sequelize-injection` | 4 in `codefixes/`, `routes/login.ts:34`, `routes/search.ts:23` |
| 5 | `run-shell-injection` | `.github/workflows/update-challenges-*.yml` |
| 4 | `express-check-directory-listing` | `server.ts:269,273,277,281` |
| 4 | `express-res-sendfile` | `routes/{fileServer,keyServer,logfileServer,quarantineServer}.ts` |
| 4 | `github-actions-mutable-action-tag` | `ci.yml`, `codeql-analysis.yml` |
| 1 | `express-open-redirect` | `routes/redirect.ts:19` |
| 1 | `hardcoded-jwt-secret` | `lib/insecurity.ts:56` |
| 1 | `code-string-concat` | `routes/userProfile.ts:61` |
| 1 | `gha-curl-pipe-shell` | `.github/workflows/ci.yml:372` |

The **41 errors** are not findings — they are files Semgrep could not fully parse (16 syntax
errors, 3 timeouts, the rest partial-parses of `.component.html` Angular templates and a few
codefix snippets). Expected on a large TS/HTML repo and, as the lab says, they do not invalidate
the run.

### A `.github/workflows/` rule, tied to Lecture 4

`github-actions-mutable-action-tag` fires at **`.github/workflows/codeql-analysis.yml:23`**:

```yaml
uses: github/codeql-action/init@v3      # mutable tag
```

This is Lecture 4's **"pin actions by SHA, not tag"** rule (Slide 7/8). A `v3` tag is a movable
pointer the upstream owner can re-point at any commit; a 40-char SHA cannot be moved. The lecture's
own case study is `tj-actions/changed-files`, where **every tag v1–v45.0.7 was re-pointed at one
malicious commit** in March 2025 — anyone on a tag ran it, anyone on a SHA did not. Note the same
repo pins its *own* `actions/checkout` by SHA (`@11bd719…` with a `#v4.2.2` comment) but leaves the
first-party `github/codeql-action` on `@v3` — exactly the "trusted-vendor" blind spot the lecture
calls out, and OWASP files under **CICD-SEC-3 (Dependency Chain Abuse)**.

### One finding I would suppress as a false positive

**`express-sequelize-injection` at `data/static/codefixes/dbSchemaChallenge_1.ts:5`.**

That rule is correct about the code — it is a raw `sequelize.query` with a concatenated
`criteria` — but the file is **dead**. `data/static/codefixes/` holds the multiple-choice answer
snippets Juice Shop *renders as text* in its "coding challenge" quiz; nothing ever `import`s or
executes them. The identical vulnerable pattern in the file that **is** wired into a route,
`routes/search.ts:23`, is the real finding. Flagging the codefix twin adds a duplicate that can
never be reached by a request, so I would suppress it — the specific reason being "not on any
import path; teaching fixture," not "SQLi is fine here." Scoping the scan with
`--exclude data/static/codefixes` drops four of the six `express-sequelize-injection` hits at once.
Upstream agrees: `codeql-analysis.yml:28` sets `paths-ignore: data/static/codefixes` for exactly
this reason.

### If I could fix one rule's worth this sprint

**`express-sequelize-injection`**, restricted to the two live routes (`routes/login.ts:34`,
`routes/search.ts:23`). It is the only ERROR-level rule whose findings are both reachable over HTTP
*and* confirmed exploitable by the ZAP active scan (below). The directory-listing and `sendfile`
warnings are information disclosure at worst; hardcoded-JWT-secret is real but one line; the shell-
injection workflow findings need push access to exploit. Authenticated SQL injection on the login
and search endpoints is the finding an external attacker reaches first, so it is the one sprint-
worth of fixes with the highest real-world payoff.

## Bonus — One bug, two tools

| OWASP | ZAP alert + URL | Semgrep rule + `file:line` |
|---|---|---|
| **A03 Injection** | SQL Injection — `GET /rest/products/search?q=%27%28` (High) | `express-sequelize-injection` — `routes/search.ts:23` |
| A03 Injection | SQL Injection — `POST /rest/user/login` (email param) | `express-sequelize-injection` — `routes/login.ts:34` |

### Strongest row: SQL injection in product search

**Vulnerable source — `routes/search.ts:21–23`:**

```ts
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

`req.query.q` goes straight into a template-string SQL query with no parameterization. Semgrep's
static rule sees the tainted `criteria` reach `sequelize.query`; ZAP proves it dynamically.

**The request ZAP used:** `GET /rest/products/search?q=%27%28` — the payload is `'(`, a single
quote plus an open paren that breaks out of the `'%…%'` literal and unbalances the parentheses. The
server answers **`HTTP/1.1 500` with `SQLITE_ERROR: near "(": syntax error`**, which is the leak: a
raw SQL parser error reflecting attacker input back is proof the input reached the database engine
unescaped. (The classic escalation from here is a `UNION SELECT` to read the `Users` table.)

**Fix I would open the PR with** — bind the input instead of interpolating it:

```ts
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :q OR description LIKE :q) AND deletedAt IS NULL) ORDER BY name',
  { replacements: { q: `%${criteria}%` }, type: QueryTypes.SELECT }
)
```

The user string becomes a bound parameter, so `'(` is treated as data, not SQL. The `login.ts:34`
row takes the same fix.

### Which finding leads the PR description

The **product-search SQL injection**, first. It is the row where both tools agree independently —
SAST points at the exact line, DAST returns a database error from a live unauthenticated request —
so there is no "is it reachable?" argument to have; it is a confirmed High. The login-page SQLi is
the same class and same fix, so it rides along in the same PR, but search leads because I
have a working request that proves it against the running app.

## Cleanup

```console
$ docker rm -f juice-shop && docker network rm lab5-net
$ rm -rf labs/lab5/semgrep/juice-shop
```

`labs/lab5/results/` and the source clone are left uncommitted, per the lab; the numbers above are
pasted from them.
