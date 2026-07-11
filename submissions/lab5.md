# Lab 5 - Submission

## Environment and setup

Commands run:

```bash
git switch -c feature/lab5
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install semgrep
semgrep --version
docker --version
jq --version
```

Observed versions:

```text
Semgrep 1.168.0
Docker version 28.3.0, build 38b7060
jq-1.7.1-apple
```

## Task 1: DAST with OWASP ZAP

### Juice Shop target

Commands run:

```bash
docker network create lab5-net 2>/dev/null || true
docker run -d --name juice-shop --network lab5-net \
  -p 127.0.0.1:3000:3000 \
  bkimminich/juice-shop:v20.0.0
until curl -s -o /dev/null http://127.0.0.1:3000/rest/products; do sleep 2; done
mkdir -p labs/lab5/results
```

Readiness check returned:

```text
Juice Shop ready
```

### Baseline unauthenticated scan

Command run:

```bash
docker run --rm --network lab5-net \
  -v "$(pwd)/labs/lab5/results:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://juice-shop:3000 \
  -r baseline-report.html -J baseline-report.json
```

Result:

```text
ZAP_BASELINE_RERUN_EXIT=2
ZAP_BASELINE_RERUN_DURATION_SECONDS=59
FAIL-NEW: 0  WARN-NEW: 8  INFO: 0  PASS: 59
```

- Duration: 59 seconds
- Total alert types: 9

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 2 |

### Authenticated full scan

Command run:

```bash
docker run --rm --network lab5-net \
  -e _JAVA_OPTIONS="-Xmx512m" \
  -v "$(pwd)/labs/lab5:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml -port 8090
```

Result:

```text
Job spider found 93 URLs
Job spiderAjax found 566 URLs
Job activeScan finished, time taken: 00:10:04
Automation plan succeeded!
ZAP_AUTH_EXIT=0
ZAP_AUTH_DURATION_SECONDS=718
```

- Duration: 718 seconds
- Total alert types: 12

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### Baseline vs authenticated comparison

Command run:

```bash
bash labs/lab5/scripts/compare_zap.sh \
  labs/lab5/results/baseline-report.json \
  labs/lab5/results/auth-report.json
```

Output:

```text
Unauthenticated Scan:
  Total alerts: 9
  High: 0
  Medium: 2
  Low: 5
  Info: 2
  Unique URLs with findings: 14

Authenticated Scan:
  Total alerts: 12
  High: 1
  Medium: 4
  Low: 3
  Info: 4
  Unique URLs with findings: 23
```

### The "10-20x more" claim

- Ratio by alert type: 12 / 9 = 1.33x.
- Ratio by alert instance: 42 / 37 = 1.14x.

This run did not match the lecture's 10-20x claim. The provided comparison counts unique ZAP alert types, not every crawled endpoint or every authenticated application state, and Juice Shop exposes a large public surface even before login. The authenticated run still found higher-value issues, including one High severity SQL injection and authenticated/stateful Socket.IO findings, but the count ratio stayed much smaller than the lecture's general rule of thumb.

### Authenticated-only alerts

| Alert | Severity | Example URI | Why baseline missed it |
|-------|----------|-------------|------------------------|
| SQL Injection | High | `http://juice-shop:3000/rest/products/search?q=%27%28` | The baseline scan is passive, while the authenticated Automation Framework run performed active attacks against parameters and triggered the SQL error. |
| Private IP Disclosure | Low | `http://juice-shop:3000/rest/admin/application-configuration` | The authenticated crawl reached the admin configuration API; the unauthenticated baseline did not crawl this authenticated/admin application state. |

## Task 2: SAST with Semgrep

### Source clone

Command run:

```bash
git clone --depth 1 --branch v20.0.0 \
  https://github.com/juice-shop/juice-shop.git \
  labs/lab5/semgrep/juice-shop
du -sh labs/lab5/semgrep/juice-shop
git -C labs/lab5/semgrep/juice-shop describe --tags --exact-match
git -C labs/lab5/semgrep/juice-shop rev-parse --short HEAD
```

Observed:

```text
81M labs/lab5/semgrep/juice-shop
v20.0.0
f356a09
```

### Semgrep scan

Command run:

```bash
semgrep \
  --config=p/owasp-top-ten \
  --config=p/javascript \
  --config=p/secrets \
  labs/lab5/semgrep/juice-shop \
  --json -o labs/lab5/results/semgrep.json \
  --severity ERROR --severity WARNING
```

Output summary:

```text
Scan completed successfully.
Findings: 22 (22 blocking)
Rules run: 151
Targets scanned: 1000
Parsed lines: ~99.9%
SEMGREP_JSON_EXIT=0
SEMGREP_JSON_DURATION_SECONDS=21
```

### Semgrep severity breakdown

Command run:

```bash
jq '[.results[].extra.severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab5/results/semgrep.json
```

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | 22 |

### Top rules by frequency

Command run:

```bash
jq '[.results[].check_id] | group_by(.) | map({rule: .[0], count: length}) |
    sort_by(-.count) | .[:10]' \
  labs/lab5/results/semgrep.json
```

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01 Broken Access Control |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A07 Identification and Authentication Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

Only seven unique rule IDs appeared in this scan, so the top-10 table is complete with seven rows.

### Triage shortcut

If I had time to fix only one rule first, I would fix `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`. It has the highest frequency, all findings are ERROR severity, and it maps to A03 Injection. More importantly, the same class is dynamically confirmed by ZAP in both `/rest/products/search` and `/rest/user/login`, so fixing the shared unsafe query-building pattern would remove several high-confidence findings at once.

### False-positive sample

I would suppress `javascript.express.security.audit.express-open-redirect.express-open-redirect` at `labs/lab5/semgrep/juice-shop/routes/redirect.ts:19` after review. Semgrep flags `res.redirect(toUrl)`, but line 16 first checks `security.isRedirectAllowed(toUrl)`, so the sink is guarded by the local redirect allowlist before the redirect executes.

## Bonus: SAST/DAST Correlation

### Cross-reference commands

Commands run:

```bash
jq -r '[.site[].alerts[].instances[].uri] | unique[]' \
  labs/lab5/results/auth-report.json | head -50 > /tmp/zap-urls.txt

jq -r '[.results[].path] | unique[]' \
  labs/lab5/results/semgrep.json | head -50 > /tmp/semgrep-paths.txt
```

Relevant overlap:

```text
ZAP: http://juice-shop:3000/rest/products/search?q=%27%28
Semgrep: labs/lab5/semgrep/juice-shop/routes/search.ts:23

ZAP: http://juice-shop:3000/rest/user/login
Semgrep: labs/lab5/semgrep/juice-shop/routes/login.ts:34
```

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection, High (Low confidence) | `/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/search.ts:23` | High overall: static taint plus dynamic 500 SQL error |
| 2 | A03 Injection | SQL Injection, High (Low confidence) | `/rest/user/login` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/login.ts:34` | High overall: same unsafe Sequelize string interpolation pattern and ZAP runtime evidence |

### Strongest correlation deep-dive

Strongest finding: SQL injection in product search.

Vulnerable code from `routes/search.ts:21-23`:

```ts
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

Working payload from ZAP:

```text
GET /rest/products/search?q=%27%28
Parameter: q
Attack: '(
Evidence: HTTP/1.1 500 Internal Server Error
```

Manual confirmation:

```bash
curl -s -i 'http://127.0.0.1:3000/rest/products/search?q=%27%28' | sed -n '1,30p'
```

Observed:

```text
HTTP/1.1 500 Internal Server Error
<title>Error: SQLITE_ERROR: near &quot;(&quot;: syntax error</title>
```

A normal search still returns 200:

```bash
curl -s -i 'http://127.0.0.1:3000/rest/products/search?q=apple' | sed -n '1,20p'
```

Observed:

```text
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
```

Proposed fix:

```ts
import { QueryTypes } from 'sequelize'

const rawCriteria = req.query.q === 'undefined' ? '' : req.query.q ?? ''
const criteria = String(rawCriteria).slice(0, 200)
const likeCriteria = `%${criteria}%`

models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
  {
    replacements: { criteria: likeCriteria },
    type: QueryTypes.SELECT
  }
)
```

This removes string interpolation from the SQL statement and passes the user-controlled value through Sequelize replacements. The length cap can remain as input shaping, but it is not a security boundary; parameterization is the actual SQL injection fix.

Why both tools caught it: Semgrep saw tainted Express request data (`req.query.q`) flow into a Sequelize raw query string. ZAP then proved the same issue dynamically by sending a quote/parenthesis payload and observing a SQLite syntax error in the HTTP 500 response.

### Reflection

Lecture 5 calls this the highest-confidence finding type because SAST and DAST remove each other's blind spots. In a real PR review, I would want the SAST finding first because it points directly to the file and unsafe line to patch; I would attach the DAST evidence next because it proves exploitability against the running service and helps prioritize the fix over static-only findings.
