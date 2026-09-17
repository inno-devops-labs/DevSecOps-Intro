# Lab 5 - SAST and DAST

## Task 1

Target image: `bkimminich/juice-shop:v20.0.0`.

ZAP command notes:
- The unauthenticated baseline used `zap-baseline.py` against `http://juice-shop:3000`.
- The authenticated run used the provided ZAP Automation Framework plan with the `admin@juice-sh.op` account, traditional spider, Ajax spider, passive scan, and active scan. The Ajax spider discovered 413 URLs, and the complete automation plan generated both report formats successfully.

| Run | Time | High | Medium | Low | Info | Total alerts | Highest risk |
|---|---:|---:|---:|---:|---:|---:|---|
| Unauthenticated baseline | 58.95s | 0 | 2 | 5 | 3 | 10 | Medium |
| Authenticated full scan | ~22m | 2 | 4 | 3 | 4 | 13 | High |

The authenticated full scan reported more alerts in total: 13 versus 10. It also found the more serious issues because it reached High-risk `SQL Injection` and `Vulnerable JS Library` alerts, while the baseline's highest level was Medium.

Authenticated-only alerts:

| Alert | URL | Why baseline did not reach it |
|---|---|---|
| `SQL Injection` | `http://juice-shop:3000/rest/products/search?q=%27%28` | The baseline only observed anonymous traffic passively, whereas the authenticated full scan discovered the Angular search request and actively mutated its `q` parameter with an SQL payload. |
| `Session ID in URL Rewrite` | `http://juice-shop:3000/socket.io/?EIO=4&transport=polling&sid=...` | The `sid` appears in Socket.IO polling traffic created while the authenticated browser session is running; the anonymous baseline did not log in or establish and crawl that session traffic. |

"Number of alerts" is a weak comparison metric because it mixes passive header findings, crawler coverage, and active exploitation evidence into one flat count. The difference here is only three alert types, but the authenticated report contains two High-risk findings while the baseline contains none. For a team lead, I would report coverage, highest risk, exploitability, and affected endpoints rather than only the total. A pipeline whose only DAST step is `zap-baseline.py` against staging can miss authenticated and active-scan-only defects, so it should add authenticated scanning for critical workflows and fail on severity/triage policy, not raw alert count.

## Task 2

Semgrep version: `1.176.0`.

Scan command:

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

Top rules:

| Count | Rule |
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

Error count: 38.

Workflow finding connected to Lecture 4: `yaml.github-actions.security.run-shell-injection.run-shell-injection` appears in `.github/workflows/update-challenges-www.yml:27` and related workflow files. This maps to CI/CD pipeline security from Lecture 4 because untrusted GitHub context interpolation inside `run:` can become command injection in the build runner and expose repository secrets.

False positive I would suppress: `routes/keyServer.ts:14`, rule `javascript.express.security.audit.express-res-sendfile.express-res-sendfile`.

The line is:

```ts
const file = params.file

if (!file.includes('/')) {
  res.sendFile(path.resolve('encryptionkeys/', file))
}
```

The rule treats `params.file` as an unrestricted path reaching `sendFile`, but this handler rejects every value containing `/` before resolving it beneath the fixed `encryptionkeys/` directory. On the Linux Juice Shop image, an absolute path and each `../` traversal segment require `/`, while a backslash is an ordinary filename character rather than a separator. I would therefore suppress this specific finding after retaining a regression test for encoded and double-encoded separators; the same rule should remain enabled elsewhere.

If I could fix one rule's findings this sprint, I would fix `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`. It has the highest count, includes runtime files such as `routes/login.ts:34` and `routes/search.ts:23`, and corresponds to exploitable OWASP A03 Injection behavior. The fix is to replace string-interpolated SQL with parameterized Sequelize queries/replacements and add regression tests for quote/comment payloads.

## Bonus

| OWASP category | ZAP alert and URL | Semgrep rule and source |
|---|---|---|
| A03: Injection | `SQL Injection` on `GET http://juice-shop:3000/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`, `routes/search.ts:23` |

Vulnerable source lines:

```ts
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

ZAP request evidence:
- Method: `GET`
- URL: `http://juice-shop:3000/rest/products/search?q=%27%28`
- Parameter: `q`
- Attack payload: `'(`
- Evidence: `HTTP/1.1 500 Internal Server Error`

Minimal reproducer:

```http
GET /rest/products/search?q=%27%28 HTTP/1.1
Host: juice-shop:3000
```

The fix I would open a PR with is to parameterize the query instead of interpolating `criteria` into SQL:

```ts
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
  {
    replacements: { criteria: `%${criteria}%` }
  }
)
```

I would put the SQL injection first in the PR description. It is independently confirmed by SAST and DAST on the same search behavior, has a concrete request-level reproducer, and maps to a high-impact OWASP Top 10 category.
