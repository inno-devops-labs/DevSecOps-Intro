# Lab 5 - Submission

## Task 1: DAST with OWASP ZAP

### Commands

```bash
docker network create lab5-net 2>/dev/null || true
docker run -d --name juice-shop --network lab5-net bkimminich/juice-shop:v20.0.0

docker run --rm --network lab5-net \
  -v "$(pwd)/labs/lab5/results:/zap/wrk" \
  zaproxy/zap-stable \
  zap-baseline.py -t http://juice-shop:3000 \
  -r baseline-report.html -J baseline-report.json

docker run --rm --network lab5-net \
  -e _JAVA_OPTIONS="-Xmx512m" \
  -v "$(pwd)/labs/lab5:/zap/wrk" \
  zaproxy/zap-stable \
  zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml -port 8090

bash labs/lab5/scripts/compare_zap.sh \
  labs/lab5/results/baseline-report.json \
  labs/lab5/results/auth-report.json
```

I used `zaproxy/zap-stable` because the GHCR pull stalled in this environment. The image is the same ZAP stable distribution. Juice Shop ran only on the Docker network because host port `3000` was already occupied by another local project.

### Baseline (unauthenticated) scan

- Duration: 5m 11s
- Total alerts: 10 alert types
- Finding instances: 43

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan

- Duration: 5m 15s
- Total alerts: 12 alert types
- Finding instances: 42

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10-20x more" claim

- Ratio by alert types: 12 / 10 = 1.2x
- Ratio by finding instances: 42 / 43 = 0.98x

This run did not match the lecture's 10-20x claim by raw count. The authenticated scan found more important issues, including a High SQL Injection finding, but the scan was bounded by `maxDuration`, `maxScanDurationInMins`, and `maxAlertsPerRule`, while the baseline already reached a lot of public SPA routes. In this run, authentication improved depth and severity more than total alert volume.

Two authenticated-scan-only alerts:

| Alert | Severity | Why baseline missed it |
|-------|----------|------------------------|
| SQL Injection on `/rest/products/search?q=...` and `/rest/user/login` | High | The authenticated Automation Framework run included active scanning and submitted attack payloads to REST parameters; the baseline scan was passive and did not exercise those inputs the same way. |
| Private IP Disclosure on `/rest/admin/application-configuration` | Low | The endpoint is part of the admin/authenticated surface reached after the logged-in spider explored application routes. |

## Task 2: SAST with Semgrep

### Commands

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git \
  labs/lab5/semgrep/juice-shop
git -C labs/lab5/semgrep/juice-shop fetch --depth 1 origin tag v20.0.0
git -C labs/lab5/semgrep/juice-shop checkout v20.0.0

python3 -m venv .venv-semgrep
.venv-semgrep/bin/pip install semgrep

.venv-semgrep/bin/semgrep \
  --config=p/owasp-top-ten \
  --config=p/javascript \
  --config=p/secrets \
  labs/lab5/semgrep/juice-shop \
  --json -o labs/lab5/results/semgrep.json \
  --severity ERROR --severity WARNING \
  --metrics=off
```

Semgrep version: `1.168.0`

### Semgrep severity breakdown

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | 22 |

### Top rules by frequency

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A03 Injection |
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03 Injection / CI command injection |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A05 Security Misconfiguration |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01 Broken Access Control |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 Broken Access Control |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A02 Cryptographic Failures |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03 Injection |

### Triage shortcut

I would fix `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` first. It is the most frequent rule, it maps to A03 Injection, and ZAP independently confirmed SQL injection at runtime. A module-level fix would replace raw string-built Sequelize queries with parameterized replacements/bind parameters in the shared route/query pattern.

### False-positive sample

I would suppress `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` for `labs/lab5/semgrep/juice-shop/server.ts:269` after review. Juice Shop intentionally exposes challenge/static directories as part of a deliberately vulnerable training app, so this is expected lab behavior rather than an accidental production misconfiguration.

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/search.ts:23` | High - both tools agree |
| 2 | A03 Injection | SQL Injection | `/rest/user/login` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/login.ts:34` | High - both tools agree |

### Strongest correlation deep-dive

Vulnerable code from `routes/search.ts:23`:

```ts
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

ZAP evidence:

```text
Alert: SQL Injection
URI: http://juice-shop:3000/rest/products/search?q=%27%28
Parameter: q
Attack: '(
Evidence: HTTP/1.1 500 Internal Server Error
```

Proposed fix:

```ts
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
  { replacements: { criteria: `%${criteria}%` } }
)
```

Both tools caught it because the tainted request parameter `req.query.q` flows into a raw SQL string and the running app also produces a server error when ZAP injects SQL metacharacters into the same parameter. Semgrep proves the source-level data flow; ZAP proves the behavior is reachable at runtime.

### Reflection

For a real PR review, I would want the SAST finding first because it points directly to the unsafe line and gives the developer a concrete patch target. I would attach the DAST evidence next because it confirms exploitability and helps prioritize the issue above purely theoretical static findings.
