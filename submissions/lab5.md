# Lab 5 — SAST and DAST

## Run provenance

Run date: 2026-09-27. Semgrep CE 1.176.0; Juice Shop tag `v20.0.0`,
commit `f356a09207c7a9550eb6fc4c3945e081922cf998`.
Local JSON and logs are retained in the gitignored `labs/lab5/results/` directory.

ZAP 2.17.0 scanned the local `bkimminich/juice-shop:v20.0.0` image. The
baseline and authenticated JSON reports, timing evidence, and logs remain under
`labs/lab5/results/` (gitignored). The authenticated plan is
`labs/lab5/scripts/zap-auth-token.yaml` and its runner is
`labs/lab5/scripts/run_auth_scan.py`.

## Task 1

### Runs and counts

```bash
docker run --rm --network lab5-net -v "$PWD/labs/lab5/results:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://juice-shop:3000 -r baseline-report.html -J baseline-report.json
python3 labs/lab5/scripts/run_auth_scan.py
bash labs/lab5/scripts/compare_zap.sh \
  labs/lab5/results/baseline-report.json labs/lab5/results/auth-report.json
```

| Risk | Baseline (passive) | Authenticated (active) |
|---|---:|---:|
| High | 0 | 2 |
| Medium | 2 | 10 |
| Low | 5 | 7 |
| Informational | 3 | 3 |
| **Alert types, total** | **10** | **22** |
| URLs with findings | 16 | 25 |
| Wall time | 56.99 s | 481.54 s (8 min 1.54 s) |

Counts are alert objects in `.site[].alerts[]`, not individual instances. The
baseline emitted 8 `WARN-NEW` policy statuses although its JSON records 10 alert
types; those counters are different measures. The authenticated run reported more
alert types **and** more serious results: two High alerts versus a Medium maximum
in the baseline. The baseline exit code was 2 because findings are present; the
authenticated automation exited 0 after generating both reports.

### Authentication evidence

Juice Shop returns `authentication.token` from `/rest/user/login`.
`run_auth_scan.py` adds it as a bearer header for API routes and as a cookie for
routes that read `req.cookies.token`. Before and after ZAP, `/rest/user/whoami`
returned status 200 with `admin@juice-sh.op`, user ID 1. An anonymous request to
`/rest/basket/1` or `/api/Users/` returned 401; each returned 200 with the token.
`/profile` returned 500 anonymously and 200 with the token.

Two alert types absent from the baseline and tied to this protected profile area:

- **Cross Site Scripting (Reflected), High:** ZAP reports a `POST` to
  `http://juice-shop:3000/profile/image/url`, parameter `imageUrl`, with payload
  `javascript:alert(1);`. The handler reads `req.cookies.token` and rejects a
  request without a logged-in user, so an anonymous scan cannot exercise its
  normal response. ZAP's report records reflection; browser execution was not
  separately confirmed, so this alert needs manual validation.
- **Absence of Anti-CSRF Tokens, Medium:** ZAP reports
  `http://juice-shop:3000/profile`, showing the profile update and image forms
  without a recognised anti-CSRF field. The profile page returned 500 without a
  session and 200 with the token, so the anonymous crawl could not inspect those
  forms. A follow-up should check the server's request validation and cookie
  behaviour before treating a missing form token as an exploitable CSRF issue.

These totals mix passive header observations with active payload findings and depend
on the URLs and forms each run reaches. A larger count by itself would say little
about impact; here the High alerts and the 401-to-200 coverage checks explain why
the active run is more useful. I would report confirmed exploitability, highest
risk, affected endpoints and roles, coverage limits, and owners to a team lead.
A pipeline that only runs `zap-baseline.py` against staging leaves protected
workflows and active payload tests unexamined, so its green or low-count result
cannot stand for full DAST coverage.

### Scan limit

The first authenticated attempt exhausted Docker memory during ZAP's DOM-XSS
browser rule and was stopped; its log is retained as `auth-aborted.log`. The
successful rerun capped the container at 2 GB, used two active worker threads,
and disabled only rule 40026 (DOM XSS). The browser crawl still ran. ZAP also
skipped checks requiring an out-of-band callback service because none was
configured. The reported totals and duration are from the successful rerun.

## Task 2

### Command and measured results

```bash
semgrep --config=p/owasp-top-ten --config=p/javascript --config=p/secrets \
  --severity ERROR --severity WARNING --json \
  -o labs/lab5/results/semgrep.json labs/lab5/semgrep/juice-shop
```

| Severity | Findings |
|---|---:|
| ERROR | 13 |
| WARNING | 14 |
| Total | 27 |

The JSON contains **39 errors**, including syntax and partial-parsing diagnostics.
The scan ran 156 rules over 1,000 files; 4 files exceeded the size limit and 140
matched ignore patterns. Rule packs are fetched from the registry, so these counts
are a dated snapshot even with a pinned scanner and source tag.

### Rule frequencies

There are nine distinct rules, so the requested top-ten table contains nine rows.

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

### Workflow finding and Lecture 4

`yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag`
flags `.github/workflows/codeql-analysis.yml:23` (also lines 34 and 36, and
`ci.yml:202`). Mutable action references let an upstream tag change alter the code
executing in the pipeline. Lecture 4's dependency-chain and pipeline integrity
controls apply: pin actions to reviewed commit SHAs and automate reviewed updates.

### A specific false positive

For the Linux container target, I would suppress only the path-traversal warning
`javascript.express.security.audit.express-res-sendfile.express-res-sendfile`
at `routes/keyServer.ts:14`, after recording the deployment assumption. The code is:

```typescript
const file = params.file
if (!file.includes('/')) {
  res.sendFile(path.resolve('encryptionkeys/', file))
}
```

Express supplies the decoded parameter before this check, so encoded forward slashes
are rejected too. On Linux a backslash is a filename character, not a path separator;
`..` alone resolves to a directory, which `sendFile` does not serve as a file. Thus
this specific input cannot select a file outside the intended directory on this
platform. This does not justify suppressing the other `sendFile` findings or ignoring
whether individual key files should be publicly accessible; a Windows deployment
would also require a different review.

### One rule to fix this sprint

Prioritise `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`.
It has six matches, but four are teaching snippets under `data/static/codefixes/`;
the two production-route matches are `routes/login.ts:34` and `routes/search.ts:23`.
User-controlled strings reach SQL interpolation, affecting authentication and product
search. Use bound parameters or ORM predicates in both routes and add regression
checks for quotes and SQL payloads. Report two application sinks, not six independently
exploitable endpoints.

## Bonus

| OWASP Top 10:2025 | ZAP alert and request URL | Semgrep rule and source |
|---|---|---|
| [A05 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) | High `SQL Injection`, `GET http://juice-shop:3000/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`, `routes/search.ts:23` |

The vulnerable source is:

```typescript
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

ZAP sent `q=%27%28`, or `'(` after decoding, and reported a `500 Internal Server
Error` instead of the normal search response. This is a working request from the
saved ZAP report; the 500 alone is an error signal rather than proof of data
extraction. The source line shows the mechanism: `criteria` enters SQL syntax
without binding, and Semgrep flags the same route. The endpoint is public, so this
row connects the **active** test to the source finding, not the authenticated
identity specifically. The passive baseline did not attack it.

The PR fix should bind the LIKE pattern as a value and validate that `q` is a
string. For Sequelize, use a constant query such as
`name LIKE :pattern OR description LIKE :pattern` with
`replacements: { pattern: `%${criteria}%` }`, preserving the length limit.
Add a regression check for quote and SQL-operator inputs and verify the error
is gone. I would lead the PR with the public search injection: it is reachable
without login and both tools locate the same sink. The protected profile XSS
alert is also High, but its browser execution still needs confirmation.
