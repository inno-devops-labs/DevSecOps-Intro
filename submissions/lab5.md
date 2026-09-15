# Lab 5 — Submission

## Task 1

### Scan durations and alert counts

| | Unauthenticated baseline | Authenticated full scan |
|-|--------------------------|------------------------|
| Duration | ~57 sec | ~4 min 30 sec |
| High | 0 | 2 |
| Medium | 2 | 4 |
| Low | 5 | 3 |
| Info | 3 | 4 |
| **Total** | **10** | **13** |

### Which run found more, and which found the serious ones?

By raw count the authenticated scan found more (13 vs 10). By severity it's not even close: the baseline found zero High alerts, while the authenticated scan found two High findings — SQL Injection and Vulnerable JS Library. The baseline never actively attacked anything, and it could only see the public surface. The authenticated run spidered 523 URLs (vs 93) and actively probed them, which is how it got to the login form and the search endpoint.

### Two alerts only the authenticated scan found

**1. SQL Injection — `http://juice-shop:3000/rest/products/search?q=%27%28`**  
The search endpoint requires no auth header, but ZAP only discovered it while spidering as the admin user — the link to `/rest/products/search` lives inside the Angular app's routing table and is never returned by the public Spider. An anonymous request to the search API would work technically, but ZAP's passive baseline never crawled deep enough to find the URL.

**2. Session ID in URL Rewrite — `http://juice-shop:3000/socket.io/?EIO=4&...&sid=...`**  
The socket.io endpoint is set up after login: the WebSocket handshake happens when an authenticated user navigates to the dashboard. The session ID leaking into the URL is visible only in requests that follow a successful login; the baseline never reaches those URLs because it doesn't authenticate.

### Why "number of alerts" is misleading

The baseline produced 10 alerts almost entirely from passive header checks — every URL it visited generated a separate Low or Info finding for the same missing header. If the baseline visited 200 pages it would report 200 "Cookie Without SameSite Attribute" alerts. The authenticated run concentrated on a smaller set of endpoints and deduplicated passive alerts, so it came out with 13 total despite being far more thorough. A meaningful comparison looks at the highest risk level found, not the count. For a team lead I'd report: "baseline found no High/Critical issues, authenticated found two High (SQL Injection and Vulnerable JS Library) — neither would have been caught in CI if the pipeline only runs zap-baseline.py."

A pipeline that only runs `zap-baseline.py` against staging will always miss vulnerabilities that require authentication — any endpoint behind a login, any behaviour that only fires after a session is established. For this app that includes the two most serious findings.

---

## Task 2

### Semgrep results

| Severity | Count |
|----------|-------|
| ERROR | 13 |
| WARNING | 14 |
| **Total** | **27** |

Parse/scan errors: **38**

### Top 10 rules by finding count

| Count | Rule |
|-------|------|
| 6 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| 5 | `yaml.github-actions.security.run-shell-injection.run-shell-injection` |
| 4 | `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` |
| 4 | `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` |
| 4 | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` |
| 1 | `javascript.express.security.audit.express-open-redirect.express-open-redirect` |
| 1 | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` |
| 1 | `javascript.lang.security.audit.code-string-concat.code-string-concat` |
| 1 | `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` |

### GitHub Actions rule and connection to Lecture 4

Rule: `yaml.github-actions.security.run-shell-injection.run-shell-injection`  
File: `.github/workflows/update-challenges-www.yml:27`

The rule flags `${{ github.event.* }}` interpolated directly into a `run:` shell step. Lecture 4 covered CI/CD pipeline security and specifically supply chain attacks via untrusted input in workflow files — an attacker who controls a PR title or issue body can inject shell commands if the workflow drops that value straight into a `run:` step without sanitising it. This is the same class of vulnerability Lecture 4 covered when discussing the `tj-actions/changed-files` incident.

### False positive: `express-res-sendfile` in `routes/keyServer.ts:14`

```
File:  routes/keyServer.ts, line 14
Rule:  javascript.express.security.audit.express-res-sendfile
```

The rule warns that `res.sendFile` with user-controlled input can serve arbitrary files. In this specific case the code explicitly checks `if (!file.includes('/'))` before calling `sendFile` — any attempt to traverse with `../` or an absolute path is rejected with a 403. Semgrep doesn't model that control flow; it just sees `params.file` flowing into `sendFile` and fires. The check is tight enough that path traversal is not possible here.

### One rule worth fixing this sprint

`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`  

6 findings, two of which are in real application code (`routes/login.ts:34` and `routes/search.ts:23`) — the other four are in `data/static/codefixes/` which are intentional teaching examples. Fixing the two real routes (parameterised queries instead of string concatenation) removes actual SQL injection vectors that ZAP also confirmed at runtime. It's the finding with both a Semgrep hit and a working exploit on the live app, so it's the one most clearly worth the PR.

---

## Bonus

### Correlation table

| OWASP category | ZAP alert | URL | Semgrep rule | File:line |
|----------------|-----------|-----|--------------|-----------|
| A03 Injection | SQL Injection (High) | `http://juice-shop:3000/rest/products/search?q=%27%28` | `express-sequelize-injection` | `routes/search.ts:23` |

### Vulnerable source, ZAP request, fix

**Vulnerable source (`routes/search.ts:23`):**

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

`criteria` comes straight from `req.query.q` with only a length cap — the user-supplied string is interpolated into the SQL string directly.

**ZAP request:**

```
GET /rest/products/search?q=%27%28 HTTP/1.1
Host: juice-shop:3000
```

Attack payload: `'(` — the single quote breaks out of the LIKE string and the opening parenthesis causes a syntax error, which ZAP detects as evidence of injection.

**Fix:**

Replace the template-literal query with a parameterised one using Sequelize's replacement syntax:

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name`,
  { replacements: { search: `%${criteria}%` }, type: QueryTypes.SELECT }
)
```

Sequelize will escape the value; `criteria` never touches the SQL string directly.

### What to put first in the PR description

The SQL Injection at `/rest/products/search` — because it's the only finding confirmed by two independent tools (ZAP actively exploited it at runtime, Semgrep found the exact vulnerable line in source), which removes the "might be a false positive" question immediately. The other findings are real too, but this one has a working request and a source line that point at the same behaviour, so it's the clearest case to lead with.
