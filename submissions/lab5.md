# Lab 5 — Anton Bugaev (CBS-03) — an.bugaev@innopolis.university

**Deliverables:** Task 1 (ZAP baseline + authenticated) · Task 2 (Semgrep SAST) · **Bonus Task** (one bug, two tools, +2 pts)

## Task 1

### Alert counts and duration

| Run | High (3) | Medium (2) | Low (1) | Info (0) | **Total** | Duration |
|-----|---------:|-----------:|--------:|---------:|----------:|---------:|
| Unauthenticated baseline (`zap-baseline.py`, passive) | 0 | 2 | 5 | 3 | **10** | **~83 s** (~1.4 min) |
| Authenticated Automation Framework scan | 2 | 4 | 3 | 3 | **12** | **~15 min** (spider ~18s + ajax spider ~3m + activeScan ~10m + reports) |

Commands used (Juice Shop on `lab5-net` as `juice-shop:3000`):

```bash
docker run --rm --network lab5-net -v "$(pwd)/labs/lab5/results:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 -r baseline-report.html -J baseline-report.json
# FAIL-NEW: 0 WARN-NEW: 8 PASS: 59 (exit non-zero is expected)

docker run --rm --network lab5-net -e _JAVA_OPTIONS="-Xmx512m" \
  -v "$(pwd)/labs/lab5:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml -port 8090
# Automation plan succeeded!
```

### Which run is “worse”?

The authenticated run reported **more alerts in total (12 vs 10)** and also the **more serious** ones: its highest risk is **High (3)** (SQL Injection, Vulnerable JS Library), while the baseline’s highest is only **Medium (2)** (CSP missing, Cross-Domain Misconfiguration). Totals alone would almost look similar; the risk ceiling is what changes the story.

### Two authenticated-only alerts

| Alert | URL | Why an anonymous request does not reach this finding |
|-------|-----|------------------------------------------------------|
| Session ID in URL Rewrite | `http://juice-shop:3000/socket.io/?EIO=4&transport=polling&...&sid=B9GmOfEz7kF9IbuCAAAA` | The `sid` is a live Socket.IO session established after the AF login as `admin@juice-sh.op`. An anonymous baseline spider never holds that session cookie/token, so it never sees a URL rewriting a real session id. |
| Authentication Request Identified | `http://juice-shop:3000/rest/user/login` | Only the authenticated plan posts the JSON login body with admin credentials. The passive baseline never performs that login exchange, so it cannot flag the authentication request itself. |

### Why “number of alerts” is a bad comparison

Alert counts mix Info/Low header noise with High exploitability, and the two plans cover different surfaces with different techniques (passive baseline vs login + ajax spider + activeScan). A team lead needs the **highest risk**, **authenticated-only exposure**, and a short list of reproducible URLs — not “12 > 10”. For a pipeline whose only DAST step is `zap-baseline.py` against staging, that means CI will mostly gate on CSP/CORS/header warnings and can **miss High issues that only appear after login or under active attack** (here: SQL Injection). Coverage of authenticated routes and at least one active job is the implication, not a different HTML reporter.

## Task 2

### Semgrep severity / top rules / errors

```bash
git clone --depth 1 --branch v20.0.0 \
  https://github.com/juice-shop/juice-shop.git labs/lab5/semgrep/juice-shop
semgrep --config=p/owasp-top-ten --config=p/javascript --config=p/secrets \
  --severity ERROR --severity WARNING \
  --json -o labs/lab5/results/semgrep.json labs/lab5/semgrep/juice-shop
```

| Severity | Count |
|----------|------:|
| ERROR | 13 |
| WARNING | 14 |
| **Total findings** | **27** |
| `errors` (parse/timeouts) | **85** |

Top rules by frequency:

| n | Rule |
|--:|------|
| 6 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` |
| 5 | `yaml.github-actions.security.run-shell-injection.run-shell-injection` |
| 4 | `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` |
| 4 | `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` |
| 4 | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` |
| 1 | `javascript.express.security.audit.express-open-redirect.express-open-redirect` |
| 1 | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` |
| 1 | `javascript.lang.security.audit.code-string-concat.code-string-concat` |
| 1 | `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` |

Run duration: **~75 s**.

### Workflow-file rule ↔ Lecture 4

Rule `yaml.github-actions.security.run-shell-injection.run-shell-injection` fires on Juice Shop’s `.github/workflows/update-challenges-*.yml` (e.g. line 22/27/36). Lecture 4 treats the CI/CD pipeline as an attackable system: untrusted input interpolated into `run:` shells is classic pipeline injection / poisoned workflow context — the same class as OWASP Top 10 CI/CD risks, not an application XSS.

### False positive (specific)

**File / line / rule:** `labs/lab5/semgrep/juice-shop/server.ts:269` — `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing`.

That `express.static` / directory listing setup is intentional Juice Shop challenge surface (FTP/static teaching paths), not an accidental misconfiguration in a production route. Suppressing this hit for the challenge-serving static mounts is justified; the same rule on a real customer upload directory would not be.

### One rule to fix this sprint

I would fix **`express-sequelize-injection`** first: six ERROR hits, including `routes/search.ts` and `routes/login.ts`, and it is the same behaviour ZAP independently confirmed as High SQL Injection on `/rest/products/search`. Parameterized Sequelize queries clear a whole class of A03 Injection with clear exploit evidence.

## Bonus Task — one bug, two tools (+2 pts)

| OWASP Top 10:2025 | ZAP alert + URL | Semgrep rule + `file:line` |
|-------------------|-----------------|----------------------------|
| **A03 Injection** | SQL Injection → `http://juice-shop:3000/rest/products/search?q=%27%28` (GET, param `q`) | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` → `routes/search.ts:23` |

### Strongest row — source, request, fix

Vulnerable source (`routes/search.ts`):

```typescript
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

ZAP request (from auth active scan): `GET /rest/products/search?q=%27%28` (payload probing quote/parenthesis for SQLi).

Fix I would open a PR with: replace string interpolation with a bound replacement / Sequelize `replacements` (or `findAll` with `Op.like` on sanitized input), e.g. `query(..., { replacements: { q: '%' + criteria + '%' } })` and never concatenate raw `criteria` into SQL. Same pattern for `routes/login.ts` email/password interpolation.

### What goes first in the PR description

Lead with **SQL Injection on product search** (`search.ts:23` + ZAP High on `/rest/products/search`): both SAST and authenticated DAST independently confirm it, risk is High, and the fix is localized. Header/CSP Medium findings from the baseline are secondary noise for that PR.
