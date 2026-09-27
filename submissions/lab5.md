# Lab 5 - SAST and DAST: Reading the Code, Then Watching It Run

## Task 1



|Type|Unauth|Auth|
|---|---|---|
|High    | 0 | 2 |
|Medium  | 2 | 4 |
|Low     | 5 | 3 |
|Info    | 3 | 4 |
|URLs    | 17| 23|
|Total   | 10| 13|
|Time    | 1m| 5m|

The Authenticated scan gave more alerts and had ones oh higher risk than Unauthenticated

Two alerts:
- SQL injection, raised by auth only because that's an active alert, passive scan doesnt request
- Private ip disclosre, the scanner was never handed the url while the spider crawled


Given the 10/13 total, its a bad metric because most of unauth's threats are low. I would rather provide the high/medium threats auth returned to my team lead because those are real problems. The pipeline with only baseline is insufficient and using it is negligence, as it is blind to important stuff like injections.







## Task 2


|Severity|Count|
|---|---|
|Err|13|
|Warn|14|
|Total|27|




|Count|Type|
|---|---|
|6   |   javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection                        |
|5   |   yaml.github-actions.security.run-shell-injection.run-shell-injection                       |
|4   |  javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing                       |
|4   |   javascript.express.security.audit.express-res-sendfile.express-res-sendfile                        |
|4   |   yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag                       |
|1   |   javascript.express.security.audit.express-open-redirect.express-open-redirect                      |
|1   |   javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret                         |
|1   |   javascript.lang.security.audit.code-string-concat.code-string-concat                       |
|1   |   yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell                       |
|41|Total|


Only 4 of the 27 findings are under `data/static/codefixes/` (the deliberately vulnerable teaching snippets); the other 23 are in real application code (`routes/`, `lib/`, `server.ts`) or CI config.


File `routes/quarantineServer.ts:14`, rule `express-res-sendfile` (WARNING):

yaml.github-actions.security.run-shell-injection.run-shell-injection fires 5 times, including .github/workflows/update-challenges-www.yml:27. The step interpolates ${{ github.ref_name }} directly into a run: block. As covered in Lecture 4, GitHub context values can be attacker-controlled, so unquoted interpolation enables shell injection on the runner. In pull_request_target or workflows with BOT_TOKEN, this can lead to token exfiltration. Pass the value through env: and reference it as "$REF_NAME" instead.

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

The rule flags res.sendFile(path.resolve('ftp/quarantine/', file)) because file comes from user input. This is a false positive here: !file.includes('/') rejects any value containing /, including ../ traversal, before sendFile is reached. Semgrep's taint analysis does not model this guard. Suppress this instance rather than disabling the rule globally: keyServer.ts uses the same safe pattern, while fileServer.ts and logfileServer.ts contain genuine vulnerabilities.

express-sequelize-injection — 6 findings

This is the only SAST rule matching behavior independently confirmed by ZAP as a live High. routes/search.ts:23 and routes/login.ts:34 interpolate req.query.q / req.body.email into raw models.sequelize.query() strings, creating SQL injection paths. Replace string interpolation with Sequelize parameterized replacements. This directly addresses an exploitable authentication-bypass and data-exfiltration risk.


## Bonus


| owasp | alert | rule |
|---|---|---|
| A03 Injection | SQL Injection — `GET /rest/products/search?q='(` (HTTP 500) | `express-sequelize-injection` — `routes/search.ts:23` |
| A03 Injection | SQL Injection — `POST /rest/user/login` param `email` | `express-sequelize-injection` — `routes/login.ts:34` |

Vulnerable source — `routes/search.ts:23`:
```ts
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

zap request:

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

fix:
```ts
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :q OR description LIKE :q) AND deletedAt IS NULL) ORDER BY name',
  { replacements: { q: `%${criteria}%` }, type: models.sequelize.QueryTypes.SELECT }
)
```

Sequelize then binds `criteria` as a value, so a quote in the input is data, not syntax, and the 500 (and
the UNION-based data disclosure behind it) both close. The same change applies to the `email` interpolation
in `routes/login.ts:34`.


the sql injection goes to the pr first, because of high severity, reachability from an unauthenticated endpoint, its
confirmed dynamically by ZAP *and* statically by Semgrep, and its fixable in two lines.

