# Lab 5 — SAST and DAST

I scanned OWASP Juice Shop anonymously and as an authenticated administrator,
then scanned the matching source with Semgrep. The submission branch starts
at `main`; this report is the only submitted artifact. Raw reports and the
source checkout remain local.

## Environment and reproducibility

| Item | Version or reference |
|---|---|
| Application | `bkimminich/juice-shop:v20.0.0`, Linux/amd64 |
| Source | Tag `v20.0.0`, commit `f356a09207c7a9550eb6fc4c3945e081922cf998` |
| Semgrep | `semgrep/semgrep:1.176.0` |
| ZAP | 2.17.0, `ghcr.io/zaproxy/zaproxy:stable` |
| ZAP image digest | `sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef` |
| Network | Docker `lab5-net`; target `http://juice-shop:3000` |
| Host access | `http://127.0.0.1:3000`, bound to loopback only |
| Application image digest | `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` |

ZAP used a fresh disposable application container. Interrupted authenticated attempts produced no report and are excluded from
the results below. The completed rerun used separate container memory limits
to keep active testing from exhausting the Docker environment. Semgrep's completed run
used the same source version and did not need repeating.

## Task 1

The final active run limited Juice Shop to 768 MB and one CPU, with a 256 MB
Node.js heap. ZAP had 2560 MB, two CPUs, 512 MB shared memory, and the required
512 MB JVM heap. These limits constrain the disposable test environment;
they are not application fixes.

The baseline used the supplied command, translated to PowerShell paths:

```powershell
docker run --rm --network lab5-net `
  -v "${PWD}/labs/lab5/results:/zap/wrk" `
  ghcr.io/zaproxy/zaproxy:stable `
  zap-baseline.py -t http://juice-shop:3000 `
  -r baseline-report.html -J baseline-report.json
```

Before the authenticated run, I reviewed the supplied `zap-auth.yaml` and
checked the login response. Juice Shop returns the JWT in
`authentication.token`, while the supplied plan uses cookie session management
without extracting that token. Its `.*"user".*` login check also matches the
anonymous response `{"user":{}}`, so it cannot demonstrate a successful login.

I made a local copy at `labs/lab5/results/zap-auth-effective.yaml` and used
[ZAP's header-based session management](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-header/):

```yaml
sessionManagement:
  method: headers
  parameters:
    Authorization: 'Bearer {%json:authentication.token%}'
    Cookie: 'token={%json:authentication.token%}'
```

I retained JSON login with the assignment's administrator account and made
the poll check require `"email":"admin@juice-sh.op"`; an empty `user` object
means logged out. The unresolved `Bearer {%token%}` poll header was removed.
The Authorization header covers API routes, while the cookie covers routes
such as `/profile` and `/rest/user/whoami`.

To give the SPA scan explicit starting points, I added a `requestor` job as
`admin` for `/rest/user/whoami`, `/profile`, `/api/Users/`, `/rest/basket/1`,
and `/rest/products/search?q=apple`, each expecting HTTP 200. The AJAX spider
used one headless Firefox browser with logout avoidance. The original time
limits remained: five minutes for the traditional spider, ten for AJAX,
five for the passive queue, and ten for the active scan, with two per rule.
An additional `traditional-json-plus` report saved HTTP evidence locally.

```powershell
docker run --rm --network lab5-net `
  --memory 2560m --memory-swap 2560m --cpus 2 --shm-size 512m `
  -e _JAVA_OPTIONS="-Xmx512m" `
  -v "${PWD}/labs/lab5:/zap/wrk" `
  ghcr.io/zaproxy/zaproxy:stable `
  zap.sh -cmd -autorun /zap/wrk/results/zap-auth-effective.yaml -port 8090
```

Both final ZAP runs completed on 21 September 2026. I ran the supplied
`compare_zap.sh` against their JSON reports, using a local copy with LF line
endings because the Windows checkout uses CRLF.

| Result | Anonymous baseline | Authenticated active scan |
|---|---:|---:|
| High | 0 | 3 |
| Medium | 2 | 10 |
| Low | 5 | 7 |
| Informational | 3 | 4 |
| **Total** | **10** | **24** |
| URLs with findings | 15 | 30 |
| Wall-clock duration | 71.87 s (1 min 12 s) | 422.77 s (7 min 3 s) |
| Process exit code | 2 (warnings found) | 0 |

The authenticated active run reported more alerts, **24 versus 10**, and
the more serious ones: its highest risk was **High**, compared with **Medium**
in the baseline. Its three High alert groups were reflected XSS, SQL injection,
and a vulnerable JavaScript library. These are scanner classifications, not
three independently proven exploits; the SQL injection is examined below.
The automation plan reported no errors or warnings. The traditional spider
found 184 URLs and the AJAX spider found 193; those overlapping crawl counts
are not the same measure as URLs with findings.

Counts mean entries in `.site[].alerts[]`, matching `compare_zap.sh`; they
are not the number of affected URLs or HTTP requests. Informational alerts
are included in the total. Run times include container startup and report
generation, but exclude downloading the scanner image.

Two alert types absent from the baseline came from the protected profile:

| Authenticated-only alert | Risk | URL and evidence | Why the anonymous run could not inspect it |
|---|---|---|---|
| Absence of Anti-CSRF Tokens (`10202`) | Medium | `http://juice-shop:3000/profile`: the profile and image-upload forms have no recognized anti-CSRF token. | Without the session cookie, this route returned HTTP 500 with `Blocked illegal activity`, so the anonymous response did not contain the forms. |
| CSP: script-src unsafe-eval (`10055-10`) | Medium | `http://juice-shop:3000/profile`: `script-src 'self' 'unsafe-eval'`. | The authenticated profile response carried this policy; an anonymous request was blocked before reaching that page. |

Both observations concern the protected page's response, not simply a URL
missed by the baseline crawler. Direct checks against the final container
returned HTTP 200 for `/profile` with the administrator session and the
blocked response without it; `/rest/user/whoami` confirmed the administrator
email only with the session. The scan's authenticated requestor also reached
`/api/Users/` and `/rest/basket/1` successfully; separate anonymous probes
returned 401. The missing-token alert still needs CSRF exploitability review,
and the CSP alert describes a weakened policy rather than proof of XSS.

The SQL injection in product search is different: that route is public.
It appeared in the active run because ZAP sent attack payloads; its absence
from the passive baseline does not mean authentication is needed to exploit it.

Alert totals alone hide differences in authentication, endpoint coverage,
and passive versus active testing, and repeated header findings can outweigh
a single serious injection in the count. I would report the highest confirmed
risks, affected routes and roles, reproducible requests, and coverage gaps to
a team lead. A pipeline that only runs `zap-baseline.py` against staging has
a useful passive check but leaves authenticated behavior and active attack
paths untested. It should add verified login and representative protected
workflows, with active scans in a disposable test environment and findings
triaged by impact rather than the raw total.

## Task 2

The source checkout was pinned to the running version:

```powershell
git clone --depth 1 --branch v20.0.0 `
  https://github.com/juice-shop/juice-shop.git labs/lab5/semgrep/juice-shop

docker run --rm -v "${PWD}:/src" -w /src semgrep/semgrep:1.176.0 `
  semgrep --config=p/owasp-top-ten --config=p/javascript --config=p/secrets `
  --severity ERROR --severity WARNING --metrics=off `
  --json -o labs/lab5/results/semgrep.json labs/lab5/semgrep/juice-shop
```

The run finished in **220.15 seconds** with exit code 0. The summary reports
156 rules run across 1000 files; the registry configurations are live rule
sets, so pinning the engine alone does not freeze future scan results.

| Severity | Findings |
|---|---:|
| ERROR | 13 |
| WARNING | 14 |
| **Total** | **27** |

| Rule | Findings |
|---|---:|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 |
| `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | 4 |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 |
| `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` | 1 |

There are only nine distinct matching rules, so the top-ten query returns
nine rows. Four findings are in `data/static/codefixes/` teaching snippets;
the remaining 23 are in application or workflow files. Those snippets remain
in the raw counts, but they are not used as evidence of an exploitable route.

The JSON contains **53 errors**: 16 syntax errors, 23 partial-parsing errors,
and 14 timeouts. Examples include deliberately incomplete codefix snippets,
Angular templates, a bundled JavaScript asset, and a secrets rule timing out
on translation JSON. The log also reports four files skipped above the 1 MB
limit and 140 ignored files. Exit code 0 means the scan completed; it does not
mean the application is clean or every file was fully analyzed.

**Workflow finding.**
`yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` flags
`.github/workflows/ci.yml:372`:

```yaml
run: curl https://cli-assets.heroku.com/install.sh | sh
```

This downloads a script and immediately executes it on the release runner.
It illustrates Lecture 4's point that the build pipeline is an attack surface:
a compromised distribution endpoint could execute code in a privileged CI job,
even if the application source passed review. I would use a pinned installer
with verified integrity and restrict the job's credentials and permissions.

**Finding I would suppress after review.** The path-traversal warning
`javascript.express.security.audit.express-res-sendfile.express-res-sendfile`
at `routes/keyServer.ts:14` overstates this specific Linux handler's behavior:

```typescript
const file = params.file

if (!file.includes('/')) {
  res.sendFile(path.resolve('encryptionkeys/', file))
} else {
  res.status(403)
  next(new Error('File names cannot contain forward slashes!'))
}
```

Express decodes the route parameter before the slash check, so encoded `/`
does not bypass it. On the scanned Linux target, a backslash is an ordinary
filename character, and a bare `..` resolves to a directory rather than a
readable arbitrary file. Direct probes for encoded slash, backslash, and
`..` returned 403; a double-encoded traversal string returned 404, and none
returned the parent `package.json`. I would suppress only this traversal
finding for this handler and deployment, and revisit it for Windows or
attacker-controlled symlinks; intentionally exposed key files and directory
listing are separate issues, not disproved by this review.

**One rule to address this sprint.** I would prioritize
`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`.
Its six findings include four teaching snippets and two live sinks,
`routes/login.ts:34` and `routes/search.ts:23`. Replacing those raw SQL
interpolations with parameter binding directly protects authentication and
database queries; the fix scope would focus on live code and regression tests,
not count changes to teaching snippets as production risk reduction.

## Bonus

| OWASP Top 10:2025 category | ZAP alert and URL | Semgrep rule and source |
|---|---|---|
| [A05: Injection](https://top10.owasp.org/2025/A05_2025-Injection/) | SQL Injection (`40018`), High risk / Low confidence; `http://juice-shop:3000/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`; `routes/search.ts:23` |

In the [pinned source](https://github.com/juice-shop/juice-shop/blob/f356a09207c7a9550eb6fc4c3945e081922cf998/routes/search.ts#L21-L23),
lines 21-23 take `q` from the request and interpolate it directly into SQL:

```typescript
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

The 200-character limit does not separate data from SQL syntax. ZAP's saved
HTTP evidence contains this request line, with `q` decoded as `'(`:

```http
GET http://juice-shop:3000/rest/products/search?q=%27%28 HTTP/1.1
Host: juice-shop:3000
```

Session headers are omitted here. The response was HTTP 500 and exposed
both the SQLite syntax error and the interpolated query:

```json
{
  "message": "SQLITE_ERROR: near \"(\": syntax error",
  "sql": "SELECT * FROM Products WHERE ((name LIKE '%'(%' OR description LIKE '%'(%') AND deletedAt IS NULL) ORDER BY name"
}
```

That error alone explains ZAP's Low confidence; it is not enough to claim
data extraction. I therefore made a separate anonymous confirmation request
with the payload below against the disposable local target:

```text
q = ')) OR 1=1--
GET /rest/products/search?q=%27%29%29+OR+1%3D1--
```

An empty search returned 46 products, all with `deletedAt: null`. The attack
returned 56, including ten soft-deleted products, confirming that input could
change the query logic and bypass `deletedAt IS NULL`. This follow-up request
is my confirmation, not a payload attributed to ZAP.

The fix I would propose replaces interpolation with a bound parameter and
handles unexpected query types before slicing. The existing result handling
after `.then(...)` can remain unchanged:

```typescript
const criteria = typeof req.query.q === 'string' && req.query.q !== 'undefined'
  ? req.query.q.slice(0, 200)
  : ''

models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE $pattern OR description LIKE $pattern) AND deletedAt IS NULL) ORDER BY name',
  { bind: { pattern: `%${criteria}%` } }
)
```

I checked this binding pattern with the application's installed Sequelize
against a separate in-memory SQLite database. Normal and empty searches
returned the expected visible product; a single quote and the injection
payload produced zero matches without SQL errors. With the vulnerable interpolated
query, the same payload exposed the hidden fixture row. The lab application
itself was left unchanged so the report describes the assigned vulnerable version.

I would lead the remediation PR with the product-search SQL injection because
both tools point to the same live sink and the follow-up request confirms a
query-logic bypass without authentication. Parameter binding removes the
cause at a small, testable boundary, making this a stronger immediate priority
than increasing the number of resolved header warnings.
