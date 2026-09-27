# Lab 5 Submission — SAST and DAST

## Task 1

### ZAP runs

Both scans targeted `bkimminich/juice-shop:v20.0.0`. The unauthenticated baseline used ZAP 2.17.0 in passive mode. The authenticated run used the supplied Automation Framework configuration with `admin@juice-sh.op` / `admin123`, spidered the authenticated surface, and ran the active scan.

| Run | Wall-clock time | High | Medium | Low | Informational | Total alerts |
|---|---:|---:|---:|---:|---:|---:|
| Unauthenticated baseline | 5m 04s | 0 | 2 | 5 | 3 | 10 |
| Authenticated active scan | 8m 28s | 2 | 4 | 3 | 4 | 13 |

The authenticated run reported more alerts overall: 13 versus 10. It also found the more serious alerts because it reached two High-risk findings, including SQL Injection; the baseline's highest risk was Medium.

The following alerts appeared only in the authenticated report:

| Alert | Risk | URL | Why the baseline did not reach it |
|---|---|---|---|
| Private IP Disclosure | Low | `http://juice-shop:3000/rest/admin/application-configuration` | This is an administrator configuration API. The baseline has no administrator JWT/session, so its anonymous crawl could not enter the administrative surface. |
| SQL Injection | High | `http://juice-shop:3000/rest/products/search?q=%27%28` | The baseline did not submit an injection payload to the product-search parameter. The endpoint is reachable without login, so this is a crawler-coverage difference rather than an access-control boundary; the authenticated run's active attack reached it. |

The number of alerts is a poor comparison metric because one alert can represent a severe exploitable issue while another is a low-impact header observation. The two scans also exercise different URL sets, authentication states, and attack techniques, so totals measure coverage and scanner behavior together. I would report severity-weighted counts, unique affected URLs, confidence, reproducibility, and confirmed exploitability to a team lead. A pipeline that runs only `zap-baseline.py` against staging provides useful passive header and configuration coverage, but it does not test authenticated paths or active injection behavior; it needs an authenticated/full scan on a controlled staging environment as a separate gate or scheduled job.

### Commands and comparison output

```bash
docker run --rm --network lab5-net -v "$(pwd)/labs/lab5/results:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 -r baseline-report.html -J baseline-report.json
# FAIL-NEW: 0  WARN-NEW: 8  PASS: 59


docker run --rm --network lab5-net -e _JAVA_OPTIONS="-Xmx512m" \
  -v "$(pwd)/labs/lab5:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml -port 8090
# Automation plan succeeded!
# Active scan: 7m 16s; reports generated: auth-report.html, auth-report.json

bash labs/lab5/scripts/compare_zap.sh \
  labs/lab5/results/baseline-report.json labs/lab5/results/auth-report.json
```

The comparison script printed:

```text
Unauthenticated Scan:
  Total alerts: 10
  High: 0
  Medium: 2
  Low: 5
  Info: 3
  Unique URLs with findings: 16

Authenticated Scan:
  Total alerts: 13
  High: 2
  Medium: 4
  Low: 3
  Info: 4
  Unique URLs with findings: 23
```

## Task 2

### Semgrep results

I cloned the Juice Shop source at tag `v20.0.0` and ran Semgrep 1.136.0 with `p/owasp-top-ten`, `p/javascript`, and `p/secrets`. The scan covered 1,113 tracked files and produced 27 findings. The command completed successfully; the JSON report contained 40 parser/analysis errors, which were recorded as expected scan errors.

```bash
semgrep --config=p/owasp-top-ten --config=p/javascript --config=p/secrets \
  --severity ERROR --severity WARNING \
  --json -o labs/lab5/results/semgrep.json \
  labs/lab5/semgrep/juice-shop
```

Severity split:

| Severity | Count |
|---|---:|
| ERROR | 13 |
| WARNING | 14 |
| **Total** | **27** |

The top rule counts were:

| Findings | Rule |
|---:|---|
| 6 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| 5 | `yaml.github-actions.security.run-shell-injection.run-shell-injection` |
| 4 | `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` |
| 4 | `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` |
| 4 | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` |
| 1 | `javascript.express.security.audit.express-open-redirect.express-open-redirect` |
| 1 | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` |
| 1 | `javascript.lang.security.audit.code-string-concat.code-string-concat` |
| 1 | `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` |

The command `jq '.errors | length' labs/lab5/results/semgrep.json` printed `40`.

### Workflow finding and Lecture 4

Semgrep flagged `.github/workflows/ci.yml:372` with `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell`. The workflow runs `curl https://cli-assets.heroku.com/install.sh | sh`, which executes remote content directly in the CI runner. This connects to Lecture 4's **CICD-SEC-8, Ungoverned Use of Third-Party Services**, and also creates a pipeline execution risk: a compromised download endpoint can execute code with the runner's permissions. The workflow also had mutable-action findings in workflow files, which connects to Lecture 4's pin-by-SHA rule and dependency-chain protection.

### False positive to suppress

I would suppress `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` at `routes/fileServer.ts:33` after review. The rule sees `res.sendFile(path.resolve('ftp/', file))` and reports possible path traversal, but this specific handler rejects any filename containing `/` at lines 16–19 and accepts only `.md`, `.pdf`, or the explicitly intended `incident-support.kdbx` file at lines 26–35. The input is therefore constrained to a single filename and an allowlisted extension before `sendFile` is called. The other `express-res-sendfile` findings require separate review because they do not all have the same validation.

### One rule to fix this sprint

I would fix `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` first. It produced six findings, includes the real product-search and login query paths, and represents direct database compromise risk. Replacing string-built SQL with Sequelize replacements/parameterized queries removes the injection sink and protects multiple entry points at once. I would then retest the ZAP SQL injection request and rerun Semgrep to confirm both the behavior and the source finding are gone.

## Bonus

| OWASP category | ZAP alert and URL | Semgrep rule and location |
|---|---|---|
| A05: Injection — SQL injection | `SQL Injection` (High), `GET http://juice-shop:3000/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`, `routes/search.ts:23` |

ZAP used the request parameter `q` with the attack string `'(`, producing a reproducible `500 Internal Server Error` and SQLite syntax error. A working request that demonstrates the same vulnerable query behavior is:

```bash
curl -sS --get 'http://127.0.0.1:3000/rest/products/search' \
  --data-urlencode "q=' OR '1'='1"
# HTTP 200 and a product list containing the query results
```

The vulnerable source is:

```ts
// routes/search.ts:21-23
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

The matching Semgrep finding identifies the tainted `req.query.q` value flowing into the Sequelize query. I would open a pull request that uses a parameterized query, for example:

```ts
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
  { replacements: { criteria: `%${criteria}%` } }
)
```

I would place this SQL injection finding first in the pull request description because both tools provide independent evidence: Semgrep identifies the exact concatenation at `routes/search.ts:23`, and ZAP reaches the running endpoint with a crafted request that causes database query failure. The combination gives the team a concrete source location, an exploitable HTTP path, and a focused parameterization fix.
