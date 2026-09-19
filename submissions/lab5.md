# Lab 5 — Submission

## Task 1

### Scan durations and alert counts

|           | Unauthenticated baseline | Authenticated full scan |
| --------- | ------------------------ | ----------------------- |
| Duration  | ~1 min 2 sec             | ~4 min 15 sec           |
| High      | 0                        | 2                       |
| Medium    | 3                        | 4                       |
| Low       | 4                        | 4                       |
| Info      | 3                        | 5                       |
| **Total** | **10**                   | **15**                  |

### Why "number of alerts" is misleading

The total number of alerts alone does not accurately represent how effective a scan was. The baseline generated 10 findings, most of them coming from passive checks of HTTP headers. The same issue can therefore be reported repeatedly for different URLs. For example, scanning 200 pages could result in 200 separate "Cookie Without SameSite Attribute" alerts.

The authenticated scan covered a substantially broader application surface and performed active testing, so its higher number of findings reflects the additional coverage rather than simply a larger number of passive alerts. The severity and nature of the findings are therefore more useful for comparing the two scans.

For a team lead I'd report: "baseline found no High/Critical issues, authenticated found two High (SQL Injection and Vulnerable JS Library) — neither would have been caught in CI if the pipeline only runs zap-baseline.py."

### Which run found more, and which found the serious ones?

The authenticated scan returned more findings overall: 15 compared with 10 from the unauthenticated baseline. More importantly, the severity distribution was different. The baseline reported no High findings, whereas the authenticated scan identified two High vulnerabilities: SQL Injection and Vulnerable JS Library.

The baseline scan did not perform authenticated active testing and therefore remained limited to the publicly accessible application surface. The authenticated run spidered 523 URLs compared with 93 for the baseline and was able to follow application behaviour that becomes available after authentication, including the login flow and the search functionality.

### Two alerts only the authenticated scan found

**1. SQL Injection — `http://juice-shop:3000/rest/products/search?q=%27%28`**

Although the search endpoint itself does not require an authentication header, the authenticated Spider was the one that discovered the `/rest/products/search` route. The endpoint is referenced by the Angular application's routing information and was not reached by the public Spider.

Consequently, an unauthenticated client could technically send a request directly to the search API, but the baseline scan did not discover the endpoint during its crawl and therefore did not test it.

**2. Session ID in URL Rewrite — `http://juice-shop:3000/socket.io/?EIO=4&...&sid=...`**

The relevant socket.io traffic occurs after authentication, when the user reaches the dashboard and the WebSocket connection is established. The session identifier appearing in the URL is therefore exposed in requests associated with a successful authenticated session.

Because the baseline scan does not log in, it never reaches this part of the application's request flow and consequently does not observe the affected URL.

A CI pipeline that only executes `zap-baseline.py` against staging has the same fundamental limitation: vulnerabilities whose endpoints or behaviour depend on authentication can remain undiscovered. In this application, that includes the two High findings identified by the authenticated scan.

---

## Task 2

### Semgrep results

| Severity  | Count  |
| --------- | ------ |
| ERROR     | 13     |
| WARNING   | 14     |
| **Total** | **27** |

Parse/scan errors: **38**

### Top 10 rules by finding count

| Count | Rule                                                                                                |
| ----- | --------------------------------------------------------------------------------------------------- |
| 6     | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`       |
| 5     | `yaml.github-actions.security.run-shell-injection.run-shell-injection`                              |
| 4     | `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` |
| 4     | `javascript.express.security.audit.express-res-sendfile.express-res-sendfile`                       |
| 4     | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag`  |
| 1     | `javascript.express.security.audit.express-open-redirect.express-open-redirect`                     |
| 1     | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret`                                |
| 1     | `javascript.lang.security.audit.code-string-concat.code-string-concat`                              |
| 1     | `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell`                              |

### GitHub Actions rule and connection to Lecture 4

Rule: `yaml.github-actions.security.run-shell-injection.run-shell-injection`

File: `.github/workflows/update-challenges-www.yml:27`

This Semgrep rule identifies cases where values from `${{ github.event.* }}` are inserted directly into a shell command executed by a GitHub Actions workflow. Such values can originate from attacker-controlled event data, including PR titles or issue content.

Without appropriate validation or sanitisation, an attacker could therefore cause additional shell commands to be executed by the workflow. This relates directly to the CI/CD and supply-chain security material from Lecture 4, including the discussion of the `tj-actions/changed-files` incident.

### False positive: `express-res-sendfile` in `routes/keyServer.ts:14`

```text
File:  routes/keyServer.ts, line 14
Rule:  javascript.express.security.audit.express-res-sendfile
```

The `express-res-sendfile` rule is intended to detect situations where input controlled by a user can be passed to `res.sendFile`, potentially allowing unintended files to be exposed.

Here, however, the application performs an explicit validation before reaching `sendFile`:

```text
if (!file.includes('/'))
```

This prevents values containing path separators, including traversal attempts such as `../`, as well as absolute paths. Such requests are rejected with a 403 response.

Semgrep reports the finding because it tracks the user-controlled value reaching `sendFile` but does not account for the particular control-flow check that occurs beforehand. In this case, the validation prevents the path traversal described by the rule.

### One rule worth fixing this sprint

`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`

The rule produced 6 findings. Two are associated with actual application routes: `routes/login.ts:34` and `routes/search.ts:23`. The remaining four occur under `data/static/codefixes/`, where they are intentional examples used for teaching.

The two findings in the application code should be addressed by replacing SQL string interpolation with parameterised queries. This is particularly significant because ZAP independently demonstrated the SQL injection behaviour at runtime.

As a result, the Sequelize injection rule provides a direct connection between static analysis and dynamic testing: Semgrep identifies the vulnerable source code, while ZAP demonstrates that the corresponding application behaviour can actually be exploited.

---

## Bonus

### Vulnerable source, ZAP request, fix

The strongest example of this correlation is the SQL injection in the product search route.

**Vulnerable source (`routes/search.ts:23`):**

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

The value of `criteria` originates from `req.query.q`. Apart from a length restriction, it is not safely separated from the SQL statement. Instead, it is inserted directly into the template literal used to construct the query.

**ZAP request:**

```text
GET /rest/products/search?q=%27%28 HTTP/1.1
Host: juice-shop:3000
```

The supplied value is `'(`. The quote character changes the SQL string context, while the opening parenthesis contributes to the resulting malformed expression. ZAP detects the resulting behaviour as evidence that the parameter is injectable.

**Fix:**

The query should use a named replacement rather than embedding `criteria` directly into the SQL text:

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name`,
  { replacements: { search: `%${criteria}%` }, type: QueryTypes.SELECT }
)
```

With this approach, the search value is supplied separately from the SQL statement. Sequelize handles the escaping of the replacement value, so `criteria` is no longer incorporated into the SQL syntax itself.

### Correlation table

The static and dynamic results point to the same vulnerability:

| OWASP category | ZAP alert            | URL                                                    | Semgrep rule                  | File:line             |
| -------------- | -------------------- | ------------------------------------------------------ | ----------------------------- | --------------------- |
| A03 Injection  | SQL Injection (High) | `http://juice-shop:3000/rest/products/search?q=%27%28` | `express-sequelize-injection` | `routes/search.ts:23` |

### What to put first in the PR description

The SQL Injection in `/rest/products/search` should be the first item described in the PR. It has evidence from both sides of the security testing process: ZAP produced a request demonstrating the vulnerable runtime behaviour, while Semgrep identified the exact source-code location responsible for constructing the unsafe query.

This combination makes the finding particularly straightforward to validate. There is both a concrete HTTP request and a corresponding vulnerable source line, rather than only a static-analysis warning that still requires manual investigation.

The other findings can be addressed separately, but this SQL injection provides the clearest connection between the automated source-code analysis and the dynamic application scan.
