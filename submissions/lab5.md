# Lab 5 — SAST and DAST

Branch: `feature/lab5`. Executed on 24–25 September 2026 (Europe/Moscow);
machine-readable run timestamps use UTC.

Target: local Linux/amd64 `bkimminich/juice-shop:v20.0.0`, exposed only on
`127.0.0.1:3000` and reached by ZAP as `http://juice-shop:3000` on `lab5-net`.
`GET /rest/admin/application-version` returned `{"version":"20.0.0"}`.
The clean source clone is tag `v20.0.0`, commit
`f356a09207c7a9550eb6fc4c3945e081922cf998`.

| Component | Version | Recorded repository digest |
| --- | --- | --- |
| Juice Shop | 20.0.0 | `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0` |
| ZAP (`ghcr.io/zaproxy/zaproxy:stable`) | 2.17.0 | `sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef` |
| Semgrep CE container | 1.176.0 | `sha256:12672acdb0949e19f9f6a4c2b288edd0b404f268f0ca7738a2c06f372f50362e` |

Docker was 29.7.2. The source and container versions match; the floating ZAP
tag is identified above so that the run can be distinguished from future pulls.
Raw reports, logs, effective scan plans, request evidence and run metadata are
kept locally in `labs/lab5/results/` for inspection and Lab 10, and are not committed.

## Task 1

### Results from the JSON reports

Counts are entries in `.site[].alerts[]`, matching `compare_zap.sh`, not requests, individual instances, or independently validated bugs.

| Risk level | Unauthenticated baseline | Authenticated active run |
| --- | ---: | ---: |
| High | 0 | 2 |
| Medium | 2 | 10 |
| Low | 1 | 6 |
| Informational | 1 | 4 |
| **Total** | **4** | **22** |
| Wall time | 562.703 s | 661.859 s |
| Exit code | 2 (warnings found) | 0 |
| Instances in JSON | 20 | 59 |
| Distinct URLs with findings | 11 | 29 |

Run intervals (UTC):

- Baseline: `2026-09-24T21:04:18.591854+00:00` to `2026-09-24T21:13:41.285920+00:00`.
- Authenticated: `2026-09-24T21:26:34.998192+00:00` to `2026-09-24T21:37:36.854791+00:00`.

The authenticated run reported more alert types (**22 versus 4**) and more serious ones: its highest level is **High**, compared with **Medium** in the baseline. Its High alerts include SQL Injection; the exact captured request and independent confirmation are in the bonus. These are scanner severities, not a claim that every alert has been manually validated.

Both required HTML and JSON reports exist. The corrected ZAP authentication
preflight returned 200 for all four protected URLs and exited 0. The final
Automation Framework run completed successfully; its log contains no native
thread exhaustion. Time and per-rule limits, ignored static-resource paths,
the seeded API surface and `maxAlertsPerRule: 10` still limit coverage.
The number of URLs with findings is not the total number of URLs tested.
The captured scanner log explicitly records the DOM XSS rule stopping at its
per-rule time cap (129.647 seconds, 165 messages, zero alerts), and Log4Shell
being skipped because no Active Scan OAST service was selected. Neither is
evidence that the corresponding vulnerability class is absent.

### Two authenticated-only alerts with actual reachability checks

| Alert | URL in the authenticated JSON | Why the anonymous request cannot inspect it |
| --- | --- | --- |
| Absence of Anti-CSRF Tokens (10202, Medium) | `http://juice-shop:3000/profile` | Without the session cookie, `getUserProfile` rejects the request with HTTP 500 before rendering the profile forms; with the admin session it returns 200 and ZAP sees the POST forms without a known anti-CSRF token. |
| CSP: script-src unsafe-eval (10055-10, Medium) | `http://juice-shop:3000/profile` | The authenticated profile response carries `script-src 'self' 'unsafe-eval'`; the anonymous error response never reaches the code that renders the profile and sets this CSP. |

Both are absent from the baseline's alert-name set. The shared URL is deliberate:
these are two distinct checks of the same protected response, not two spellings
of one alert. Evidence is the actual form markup and CSP header in the
authenticated message report, supported by the 500/200 reachability comparison
and `routes/userProfile.ts:34–36, 88–98`.

### What I would report to a team lead and put in CI

The totals (4 and 22) measure scanner output under different exploration and attack settings, so they do not measure application safety. I would report validated findings by severity and business impact, affected endpoints and roles, reproducible evidence, ownership and remediation dates, alongside authentication success, coverage gaps and scan failures. The changed login state, seeded URLs, browser exploration and active payloads all affect these totals, so this is not a controlled experiment isolating authentication alone. A pipeline running only `zap-baseline.py` against staging leaves protected workflows and active injection behavior untested; keep it as an initial check, then add verified authenticated role/API coverage and active tests against a disposable staging target, with SAST earlier in CI.

### Commands and the authentication prerequisite

Both supplied scripts were read before use. Baseline command:

```bash
docker run --rm --name lab5-baseline --network lab5-net \
  -v "$PWD/labs/lab5/results:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 \
  -r baseline-report.html -J baseline-report.json
```

During passive-queue draining, ZAP's own freshness rule **10116** repeatedly
waited up to 60 seconds for failed external update requests. I disabled only
that scanner via its local API:

```text
GET /JSON/pscan/action/disableScanners/?ids=10116
{"Result":"OK"}
```

This checks the scanner version, not a vulnerability in Juice Shop; no
application scan rule was disabled. The authenticated plan disables the same
rule from the start and uses `-silent` to avoid further update/telemetry delays.
The reported baseline wall time includes the actual delays and shutdown, not
just the one-minute spider phase. Image download and separate preflights are
excluded from the scan durations.
See the [rule description](https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules/)
and [silent-mode documentation](https://www.zaproxy.org/faq/what-calls-home-does-zap-make/).

The shipped `scripts/zap-auth.yaml` does **not** establish a usable session for
this target as written. A ZAP `requestor` preflight using its original context
and the named `admin` user produced these actual responses:

| Endpoint | Original ZAP context | Direct anonymous request | Direct authenticated request |
| --- | ---: | ---: | ---: |
| `/api/Users` | 401 | 401 | 200 |
| `/rest/user/authentication-details` | 401 | 401 | 200 |
| `/rest/basket/1` | 401 | 401 | 200 |
| `/profile` | 500 | 500 | 200 |

Juice Shop returns `authentication.token` in JSON, while the supplied plan uses
cookie-only session management. Also, the original `"user"` login regex matches
the anonymous response `{"user":{}}`. The effective plan uses these settings
under its existing context:

```yaml
authentication:
  method: json
  parameters:
    loginRequestUrl: http://juice-shop:3000/rest/user/login
    loginRequestBody: '{"email":"{%username%}","password":"{%password%}"}'
  verification:
    method: poll
    loggedInRegex: '"email"\s*:\s*"admin@juice-sh\.op"'
    loggedOutRegex: '"user"\s*:\s*\{\s*\}'
    pollFrequency: 60
    pollUnits: requests
    pollUrl: http://juice-shop:3000/rest/user/whoami
sessionManagement:
  method: headers
  parameters:
    Authorization: 'Bearer {%json:authentication.token%}'
    Cookie: 'token={%json:authentication.token%}'
```

Credentials remain the lab's `admin@juice-sh.op` / `admin123`. The Bearer header
authenticates API requests; `/profile` reads the `token` cookie. This follows
ZAP's [header-based session management](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-header/).
Direct `/rest/user/whoami` checks also verified the actual email, rather than
treating its anonymous HTTP 200 response as proof of login.

Other effective-plan changes are explicit: add a `requestor` job as `admin`
for the four protected endpoints above, `/rest/user/whoami`, and
`/rest/products/search?q=apple`; select `firefox-headless` for `spiderAjax`;
wait for passive scanning again after the active scan; and save an additional
`traditional-json-plus` report containing HTTP messages for the bonus evidence.
The existing 5-minute traditional-spider limit, 10-minute AJAX limit,
10-minute active-scan limit and 2-minute per-rule limit are retained.
The final run sets `activeScan.parameters.threadPerHost: 2` and
`_JAVA_OPTIONS='-Xmx512m -XX:ActiveProcessorCount=2'`, with Docker limits of
2 CPUs, 4 GiB and 2048 processes/threads. The first authenticated attempt
created dozens of Firefox instances, reached about 8 GiB / 7178 tasks, and
reported native-thread exhaustion. Its reports are archived separately in
`results/auth-first-run/`; they are not used for the final comparison.
Juice Shop was restarted before the final authenticated run, and readiness
and authenticated access were verified again.

The first job is:

```yaml
- type: passiveScan-config
  parameters:
    maxAlertsPerRule: 10
    enableTags: false
  rules:
  - id: 10116
    threshold: "Off"
```

Effective scan command (the original course config remains unchanged):

```bash
docker run --rm --name lab5-auth --network lab5-net \
  --cpus 2 --memory 4g --pids-limit 2048 \
  -e '_JAVA_OPTIONS=-Xmx512m -XX:ActiveProcessorCount=2' \
  -v "$PWD/labs/lab5:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -silent -autorun /zap/wrk/results/zap-auth-effective.yaml -port 8090
```
## Task 2

### Reproduction and actual output

The pre-existing, clean clone was verified before scanning:

```text
git -C labs/lab5/semgrep/juice-shop describe --tags --exact-match
v20.0.0
git -C labs/lab5/semgrep/juice-shop rev-parse HEAD
f356a09207c7a9550eb6fc4c3945e081922cf998
```

Semgrep ran in `semgrep/semgrep:1.176.0`, with the repository mounted read-only
at `/work` and the results directory mounted at `/out`. The bundled executable
initially failed with `OSError: [Errno 5] I/O error`; reinstalling the **same**
`semgrep==1.176.0` wheel inside the disposable container fixed execution.
No host Python packages or target source files were changed.

```bash
python -m pip install --break-system-packages --cache-dir /out/pip-cache \
  --force-reinstall --no-deps semgrep==1.176.0
semgrep --config=p/owasp-top-ten --config=p/javascript --config=p/secrets \
  --severity ERROR --severity WARNING --json -o /out/semgrep.json \
  labs/lab5/semgrep/juice-shop
```

```text
Ran 156 rules on 1000 files: 27 findings.
Exit code: 0
```

The initial configuration inventory contained 573 rules; the final scan summary
reported 156 rules run. The registry rule packs are fetched at execution time,
so pinning the engine and target does not freeze the registry contents.

| Severity (`.results[].extra.severity`) | Findings |
| --- | ---: |
| ERROR | 13 |
| WARNING | 14 |
| **Total** | **27** |

Top rules, ordered by count descending and then rule identifier (only nine
distinct rules matched, so the requested top ten contains nine rows):

| Count | Rule |
| ---: | --- |
| 6 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| 5 | `yaml.github-actions.security.run-shell-injection.run-shell-injection` |
| 4 | `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` |
| 4 | `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` |
| 4 | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` |
| 1 | `javascript.express.security.audit.express-open-redirect.express-open-redirect` |
| 1 | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` |
| 1 | `javascript.lang.security.audit.code-string-concat.code-string-concat` |
| 1 | `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` |

`.errors | length` is **49**: 16 `Syntax error`, 23 `PartialParsing`, and 10
`Timeout` records. There are seven timeout records in translation JSON files
and three in `frontend/src/assets/private/three.js`; records are not necessarily
distinct files. These errors and the 4 files skipped for size / 140 files
matching ignore patterns limit coverage; a successful exit does not mean every
source line was checked.

Only **4/27** findings are in `data/static/codefixes/`, all under the SQL-injection
rule: `dbSchemaChallenge_1.ts:5`, `dbSchemaChallenge_3.ts:11`,
`unionSqlInjectionChallenge_1.ts:6`, and `unionSqlInjectionChallenge_3.ts:10`.
The remaining **23** include workflow findings and application code; the two
application SQL-injection findings are `routes/login.ts:34` and
`routes/search.ts:23`. Thus the lab's warning that *most* findings are teaching
snippets does not describe this particular registry snapshot/run.

### A workflow finding and Lecture 4

`yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag`
flags `.github/workflows/codeql-analysis.yml:23`:

```yaml
uses: github/codeql-action/init@v3
```

The mutable `v3` tag can change without any modification to this workflow.
Lecture 4, slides 7–8 and 15, recommends full commit-SHA pins to address
dependency-chain abuse and ungoverned third-party actions (CICD-SEC-3/8).
I would pin all four reported action references to verified full SHAs and use
an update process to review subsequent changes, rather than freeze them forever.

### One narrowly scoped false positive

I would suppress
`javascript.express.security.audit.express-res-sendfile.express-res-sendfile`
at **`routes/keyServer.ts:14` for this pinned Linux deployment**, specifically
its claim of arbitrary file read through path traversal:

```typescript
// routes/keyServer.ts:11–14
const file = params.file

if (!file.includes('/')) {
  res.sendFile(path.resolve('encryptionkeys/', file))
```

The decoded route parameter cannot contain `/` when it reaches `sendFile`.
On the scanned Linux platform, a backslash is not a path separator, and an
isolated `..` names a directory rather than a readable file. The pinned
`encryptionkeys/` tree contains two regular files, `jwt.pub` and `premium.key`,
and no symlinks, so there is no alternate symlink path out of that directory.
This is a code- and platform-specific reason the rule's traversal claim is wrong;
it is not an argument that `path.resolve` alone makes user input safe.

Supporting live requests, made separately from the ZAP reports:

| Path | HTTP status | `package.json` exposed |
| --- | ---: | --- |
| `/encryptionkeys/jwt.pub` | 200 | No |
| `/encryptionkeys/..%2Fpackage.json` | 403 | No |
| `/encryptionkeys/..%5Cpackage.json` | 403 | No |
| `/encryptionkeys/%2E%2E` | 403 | No |
| `/encryptionkeys/%252E%252E%252Fpackage.json` | 404 | No |

These probes support, rather than replace, the source argument. I would not
apply the suppression to Windows or to a deployment allowing new symlinks.
Publicly serving `premium.key` and listing the key directory are separate
disclosure concerns and remain actionable; suppressing this traversal rule
does not dismiss them.

### One rule to fix this sprint

I would choose
`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`.
Its six hits include the real login and product-search handlers, where request
data is interpolated directly into SQL. Parameterizing those queries removes
an injection primitive affecting authentication and database confidentiality;
I would prioritize these runtime paths and track the four teaching examples
separately instead of treating six scanner rows as six deployed endpoints.


## Bonus

| OWASP category | ZAP alert and URL | Semgrep rule and source |
| --- | --- | --- |
| [A05:2025 — Injection](https://top10.owasp.org/2025/A05_2025-Injection/) | SQL Injection (40018, High): `http://juice-shop:3000/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` — `routes/search.ts:23` |
| [A05:2025 — Injection](https://top10.owasp.org/2025/A05_2025-Injection/) | SQL Injection (40018, High): `http://juice-shop:3000/rest/user/login` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` — `routes/login.ts:34` |

All source paths in this section are relative to the pinned Juice Shop clone.

### The request ZAP actually used

The strongest row is product search. The message report records method `GET`, parameter `q`, attack `'(`, and response evidence `HTTP/1.1 500 Internal Server Error`. The relevant request headers are reproduced below, with the disposable session value redacted:

```http
GET http://juice-shop:3000/rest/products/search?q=%27%28 HTTP/1.1
host: juice-shop:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Connection: keep-alive
Referer: http://juice-shop:3000/
Authorization: <redacted lab session>
Cookie: <redacted lab session>
```

The recorded HTTP 500 response included:

```json
{
  "error": {
    "message": "SQLITE_ERROR: near \"(\": syntax error",
    "code": "SQLITE_ERROR",
    "sql": "SELECT * FROM Products WHERE ((name LIKE '%'(%' OR description LIKE '%'(%') AND deletedAt IS NULL) ORDER BY name"
  }
}
```

### Source and proposed fix

The matched source is **`routes/search.ts:21–23`** at the pinned commit:

```typescript
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

Truncating input to 200 characters does not stop SQL syntax from entering the
query. The source finding is the application handler, not one of the four
`data/static/codefixes/` matches.

The PR I would open against a production version would validate `q` as a string
and bind its value separately from SQL, preserving the existing pair-shaped
Sequelize result consumed by `.then(([products]) => ...)`:

```typescript
if (req.query.q !== undefined && typeof req.query.q !== 'string') {
  res.status(400).json({ error: 'q must be a string' })
  return
}
const raw = req.query.q === 'undefined' ? '' : (req.query.q ?? '')
const criteria = raw.slice(0, 200)

models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE $criteria OR description LIKE $criteria) AND deletedAt IS NULL) ORDER BY name',
  { bind: { criteria: `%${criteria}%` } }
)
// Keep the existing .then/.catch chain and response mapping.
```

Here `$criteria` is outside SQL quotes, and `%` wildcards are part of the bound
value. [Sequelize v6 documents this separation of SQL text and bound parameters](https://sequelize.org/docs/v6/core-concepts/raw-queries/#bind-parameter).

I tested the proposed query using the target container's Sequelize/SQLite
dependencies against a separate **in-memory** database. It passed normal
`Apple` search, `Bob's` input, `apple'`, the boolean-injection string
`')) OR 1=1--`, empty/`undefined` search, and exclusion of a soft-deleted apple
record. The observed output was:

```text
PASS: normal search, apostrophe, quote payload, boolean injection, empty/undefined search, and deletedAt filtering
```

This validates the query behavior; it is not a claim that a patched application
was deployed or rescanned. The proposed fix was not applied to the target
application or its source clone.


### Independent live confirmation

ZAP's SQL alert has **Low confidence** and is based on an error response;
HTTP 500 alone would not prove SQL injection. I therefore made the following
separate, read-only requests to the running app, with `Accept: application/json`
and **no Authorization or Cookie header**:

| `q` value | HTTP | Returned product rows |
| --- | ---: | ---: |
| `lab5-no-such-product-927461` | 200 | 0 |
| `lab5-no-such-product-927461')) OR 1=1--` | 200 | 56 |
| `lab5-no-such-product-927461')) OR 1=2--` | 200 | 0 |
| `'(` (replay of ZAP's search payload) | 500 | SQLite syntax error |

Changing only the injected condition changes the result set from zero rows to
56 and back to zero. Combined with the exact source interpolation and ZAP's
recorded request/response, this establishes the shared SQL-injection behavior.
These four requests are supplemental validation, not invented ZAP findings or
additions to its alert totals.

I would put the public product-search SQL injection first in the remediation
PR description: both tools locate the same handler, and the boolean pair
demonstrates attacker control of query semantics without authentication.
The login handler has the same dangerous construction and belongs in the same
remediation scope; bulk header-warning counts should not displace this
reproducible database-access risk.


## Local evidence integrity

Raw reports remain excluded from Git. SHA-256 of the final files:

| File in `labs/lab5/results/` | SHA-256 |
| --- | --- |
| `baseline-report.json` | `653bcfc652866399b034e7b445b8f746c31b44f45f60ec4d2c6336ffa60772e8` |
| `auth-report.json` | `8371444b50e5ecc7d77650c71d419d20a2f59e906e8f7c26e13533efc4c286b1` |
| `auth-with-messages.json` | `90f310a91c653e4be103ff9f55dda99482c7850d91d3c516e8449fdd6f88c271` |
| `semgrep.json` | `68980a1e9fe82f5b23abf16818d8ee6808a424a8d2e1d80958c09d0eb71710d1` |
