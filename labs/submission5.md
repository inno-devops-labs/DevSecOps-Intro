# Lab 5 Submission — SAST & DAST of OWASP Juice Shop

## Student / Context
- Name: `Danil Fishchenko`
- Branch: `feature/lab5`
- Target image: `bkimminich/juice-shop:v19.0.0`
- Scan date: `2026-03-09`
- Host OS: `macOS`
- Main target URL: `http://localhost:3000`

## Task 1 — SAST with Semgrep

### 1.1 Environment setup
```bash
mkdir -p labs/lab5/{semgrep,zap,nuclei,nikto,sqlmap,analysis,scripts}
git clone https://github.com/juice-shop/juice-shop.git --depth 1 --branch v19.0.0 labs/lab5/semgrep/juice-shop
```

### 1.2 Semgrep execution
```bash
docker run --rm -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
  -v "$(pwd)/labs/lab5/semgrep":/output \
  semgrep/semgrep:latest \
  semgrep --config=p/security-audit --config=p/owasp-top-ten \
  --json --output=/output/semgrep-results.json /src

docker run --rm -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
  -v "$(pwd)/labs/lab5/semgrep":/output \
  semgrep/semgrep:latest \
  semgrep --config=p/security-audit --config=p/owasp-top-ten \
  --text --output=/output/semgrep-report.txt /src
```

### 1.3 SAST Tool Effectiveness
- Files scanned: `1014`
- Total findings: `25`
- Severity breakdown: `ERROR=7`, `WARNING=18`
- Coverage limitation: `37` scan issues were reported by Semgrep during analysis:
  - `20` `Syntax error`
  - `15` `PartialParsing`
  - `2` `Timeout` events on `frontend/src/assets/private/three.js`
- Main vulnerability classes detected:
  - `SQL Injection` in Sequelize-backed routes and code paths
  - `Hardcoded JWT secret` in security-related library code
  - `Path Traversal / Arbitrary File Read` in `res.sendFile` handlers
  - `Open Redirect` and `Code Injection` patterns in route handlers

Interpretation:
- The finding set is still useful, but coverage is not perfect because some files were only partially parsed or timed out during rule execution.

### 1.4 Top 5 Critical Semgrep Findings
| Rank | Vulnerability Type | File | Line | Severity | Why it matters |
|---:|---|---|---:|---|---|
| 1 | `SQL Injection` | `routes/login.ts` | 34 | `ERROR` | Authentication code touches user-controlled input, so a SQLi here can become auth bypass or credential disclosure. |
| 2 | `SQL Injection` | `routes/search.ts` | 23 | `ERROR` | Search endpoints are internet-facing and high-volume, which makes exploitation practical. |
| 3 | `Code Injection` | `routes/userProfile.ts` | 62 | `ERROR` | Server-side code execution paths are high impact because they can lead to arbitrary command or logic execution. |
| 4 | `SQL Injection` | `data/static/codefixes/dbSchemaChallenge_1.ts` | 5 | `ERROR` | Demonstrates tainted Sequelize query construction and unsafe query composition. |
| 5 | `SQL Injection` | `data/static/codefixes/unionSqlInjectionChallenge_1.ts` | 6 | `ERROR` | Shows unsafe query handling patterns that can expose schema and table data. |

## Task 2 — DAST with ZAP, Nuclei, Nikto, SQLmap

### 2.1 Start target app
```bash
docker run -d --name juice-shop-lab5 -p 3000:3000 bkimminich/juice-shop:v19.0.0
sleep 10
curl -s http://localhost:3000 | head -n 5
```

### 2.2 ZAP unauthenticated scan
```bash
docker run --rm \
  -v "$(pwd)/labs/lab5/zap":/zap/wrk/:rw \
  zaproxy/zap-stable:latest \
  zap-baseline.py -t http://host.docker.internal:3000 \
  -r report-noauth.html -J zap-report-noauth.json \
  | tee labs/lab5/zap/zap-noauth.log
```

### 2.3 ZAP authenticated scan
```bash
docker run --rm \
  -v "$(pwd)/labs/lab5":/zap/wrk/:rw \
  zaproxy/zap-stable:latest \
  zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml \
  | tee labs/lab5/zap/zap-auth.log
```

Run comparison:
```bash
bash labs/lab5/scripts/compare_zap.sh
```

### 2.4 Nuclei
```bash
docker run --rm \
  -v "$(pwd)/labs/lab5/nuclei":/app \
  projectdiscovery/nuclei:latest \
  -u http://host.docker.internal:3000 \
  -jsonl -o /app/nuclei-results.json
```

### 2.5 Nikto
```bash
docker run --rm \
  -v "$(pwd)/labs/lab5/nikto":/tmp \
  ghcr.io/sullo/nikto:latest \
  -h http://host.docker.internal:3000 -o /tmp/nikto-results.txt
```

### 2.6 SQLmap
```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /tmp/sqlmap

python3 /tmp/sqlmap/sqlmap.py \
  -u "http://localhost:3000/rest/products/search?q=*" \
  --dbms=SQLite --batch --level=3 --risk=2 \
  --technique=B --threads=5 \
  --flush-session \
  --output-dir="$(pwd)/labs/lab5/sqlmap-search"

python3 /tmp/sqlmap/sqlmap.py \
  -u "http://localhost:3000/rest/user/login" \
  --data='{"email":"*","password":"test"}' \
  --method POST \
  --headers='Content-Type: application/json' \
  --dbms=SQLite --batch --level=5 --risk=3 \
  --technique=BT --threads=5 --ignore-code=401 --flush-session \
  --output-dir="$(pwd)/labs/lab5/sqlmap" \
  --dump
```

Preserved SQLmap artifacts:
- `labs/lab5/sqlmap-search/` contains the confirmed `GET /rest/products/search?q=*` injection evidence.
- `labs/lab5/sqlmap/` contains the confirmed `POST /rest/user/login` injection evidence and dumped SQLite tables.

### 2.7 Authenticated vs Unauthenticated ZAP
- Unauthenticated URL count: `95`
- Authenticated URL count: `311`
- Delta: `+216 URLs` (`+227%` vs unauthenticated)
- Examples of authenticated/admin endpoints:
  - `http://host.docker.internal:3000/rest/admin/application-configuration`
  - Authenticated crawling also expanded discovery across account, basket, and API paths not visible to the baseline scan.
  - The authenticated spider found `169` URLs before AJAX spider expanded coverage to `311`.
- Why authenticated scanning matters:
  - It reveals role-specific and session-dependent attack surface that anonymous scans never reach.
  - It allows testing of admin and authenticated API behavior, not just public assets and headers.

### 2.8 Tool Comparison Matrix
| Tool | Findings | Severity Breakdown | Best Use Case |
|---|---:|---|---|
| ZAP | `16` | `High=1, Medium=5, Low=5, Info=5` | `Broad authenticated web application scanning with crawling and active testing` |
| Nuclei | `1` | `Critical=0, High=0, Medium=0, Low=0, Info=1` | `Fast template-based exposure checks` |
| Nikto | `152` | `No native severity split` | `Server misconfiguration review and interesting file discovery` |
| SQLmap | `2` | `2 confirmed injection targets; login run dumped 12 SQLite tables` | `Deep SQL injection verification and database dumping` |

### 2.9 Tool-Specific Strengths
- **ZAP:** Best for broad web coverage and authenticated crawling. It expanded discovery from `95` to `311` URLs and exposed the authenticated admin endpoint `/rest/admin/application-configuration`, while also reporting issues such as missing CSP and cross-origin policy weaknesses.
- **Nuclei:** Best for very fast template-driven exposure checks. It immediately found a public Swagger API exposure at `/api-docs/swagger.json` with template id `swagger-api`.
- **Nikto:** Best for server hardening review. It highlighted missing `Strict-Transport-Security`, `Content-Security-Policy`, `Permissions-Policy`, and `Referrer-Policy` headers, along with accessible locations such as `/ftp/`.
- **SQLmap:** Best for confirming exploitability of injection findings. It verified boolean-based blind SQL injection against `GET /rest/products/search?q=*` and verified boolean-based blind plus time-based blind SQL injection against `POST /rest/user/login`. The login run fingerprinted the backend as `SQLite` and dumped multiple tables such as `Products`, `Feedbacks`, `SecurityAnswers`, and `PrivacyRequests`.

## Task 3 — SAST/DAST Correlation

### 3.1 Result counts
- SAST findings: `25`
- DAST findings combined (rough cross-tool artifact count): `171`

This DAST total is only an approximate comparison because each tool counts different units: ZAP counts alert types from the summary table, Nuclei counts template matches, Nikto counts reported request-level items, and SQLmap here is counted as `2` confirmed vulnerable targets rather than by dumped tables.

### 3.2 Vulnerabilities found only by SAST
- `Hardcoded secret detection` such as the JWT secret in `lib/insecurity.ts`
- `Code injection patterns` in route logic before runtime exploitation is attempted
- `Unsafe file handling and open redirect code paths` visible directly in source
- Additional risky source patterns in files that DAST did not explicitly exercise during this run

### 3.3 Vulnerabilities found only by DAST
- `Missing or weak security headers` observed in live HTTP responses
- `Publicly exposed runtime assets` such as `/api-docs/swagger.json`, `/robots.txt`, and `/ftp/`
- `Authenticated attack surface expansion` including `/rest/admin/application-configuration`

### 3.4 Why results differ
SAST inspects source code and finds insecure patterns before runtime. DAST exercises the running application and reveals runtime behavior, deployed headers, auth/session handling, exposed routes, and server-side weaknesses that static pattern matching cannot confirm directly.

## Security Recommendations
- Replace unsafe raw query construction with parameterized Sequelize queries and validate all user-controlled query input.
- Remove hardcoded secrets from source code and load them from environment variables or a dedicated secret manager.
- Harden response headers by adding CSP, HSTS, Referrer-Policy, and Permissions-Policy, and review permissive CORS settings.
- Restrict or disable unnecessary exposures such as public Swagger documentation, backup-like files, and admin endpoints without stronger access controls.
- Treat authenticated DAST as mandatory in CI/CD because the authenticated scan discovered `227%` more URLs than the unauthenticated baseline.

## Evidence Files
- `labs/lab5/semgrep/semgrep-results.json`
- `labs/lab5/semgrep/semgrep-report.txt`
- `labs/lab5/zap/zap-report-noauth.json`
- `labs/lab5/zap/report-noauth.html`
- `labs/lab5/zap/report-auth.html`
- `labs/lab5/nuclei/nuclei-results.json`
- `labs/lab5/nikto/nikto-results.txt`
- `labs/lab5/sqlmap-search/`
- `labs/lab5/sqlmap/`
- `labs/lab5/analysis/`
