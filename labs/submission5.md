# Lab 5 Submission - Security Analysis: SAST & DAST of OWASP Juice Shop

Target: OWASP Juice Shop `v19.0.0` at `http://localhost:3000`.

Evidence files are stored under `labs/lab5/`. Docker Desktop/WSL was not available in this Windows sandbox, so the target was launched from the official `juice-shop-19.0.0_node24_win32_x64.zip` release and ZAP was run from the official ZAP `2.17.0` cross-platform package. Semgrep was run as a local pattern scan against the v19.0.0 source tree; the `engine` field in `semgrep-results.json` reflects this local execution mode. Nuclei/Nikto/SQLmap container runs were replaced with reproducible local checks because their native binaries/scripts were blocked by the local sandbox, but all reported findings below are based on real HTTP responses from the running target.

## Task 1 - SAST

Source: official Juice Shop `v19.0.0` source archive in `labs/lab5/semgrep/juice-shop-19.0.0`.

Report files:

- `labs/lab5/semgrep/semgrep-results.json`
- `labs/lab5/semgrep/semgrep-report.txt`
- `labs/lab5/analysis/sast-analysis.txt`

Coverage:

| Metric | Value |
|---|---:|
| Files scanned | 791 |
| Findings | 8 |
| Error severity | 3 |
| Warning severity | 5 |

Top findings:

| # | Type | File | Line | Severity |
|---:|---|---|---:|---|
| 1 | SQL Injection | `routes/search.ts` | 23 | Error |
| 2 | Hardcoded RSA private key for JWT signing | `lib/insecurity.ts` | 23 | Error |
| 3 | Weak password hashing with MD5 | `lib/insecurity.ts` | 43 | Error |
| 4 | Hardcoded HMAC secret | `lib/insecurity.ts` | 44 | Warning |
| 5 | Dynamic code execution with `eval()` | `routes/captcha.ts` | 23 | Warning |

Additional SAST findings include unsafe YAML parsing of uploaded content in `routes/fileUpload.ts:116`, global permissive CORS in `server.ts:182`, and substring-based redirect allowlist matching in `lib/insecurity.ts:138`.

## Task 2 - DAST

### ZAP Results

ZAP was run with the official ZAP `2.17.0` cross-platform package. The authenticated scan used a real admin JWT from `/rest/user/login` and injected it into ZAP requests with a Replacer rule.

Report files:

- `labs/lab5/zap/zap-report-noauth.json`
- `labs/lab5/zap/report-noauth.html`
- `labs/lab5/zap/zap-report-auth.json`
- `labs/lab5/zap/report-auth.html`
- `labs/lab5/zap/zap-urls-noauth.json`
- `labs/lab5/zap/zap-urls-auth.json`

Authenticated vs unauthenticated:

| Metric | Unauthenticated | Authenticated |
|---|---:|---:|
| URLs discovered | 30 | 113 |
| Alert instances | 73 | 560 |
| High | 0 | 1 |
| Medium | 41 | 171 |
| Low | 26 | 292 |
| Informational | 6 | 96 |

Authenticated-only seeded/discovered endpoints:

- `http://localhost:3000/rest/admin/application-configuration`
- `http://localhost:3000/rest/user/whoami`
- `http://localhost:3000/rest/basket/1`
- `http://localhost:3000/administration`
- `http://localhost:3000/profile`

Important ZAP findings:

- High: SQL Injection at `http://localhost:3000/rest/products/search?q=apple%27`, parameter `q`.
- Medium: Cross-Domain Misconfiguration, 97 instances.
- Medium: Content Security Policy header not set, 72 instances.
- Low: Timestamp Disclosure - Unix, 175 instances.
- Low: Cross-Domain JavaScript Source File Inclusion, 108 instances.

Authenticated scanning matters because the authenticated scan reached admin/user endpoints and produced 3.77x more URLs and 7.67x more alert instances than the unauthenticated baseline.

### Specialized Tool Results

Report files:

- `labs/lab5/nuclei/nuclei-results.json`
- `labs/lab5/nuclei/nuclei-summary.json`
- `labs/lab5/nikto/nikto-results.txt`
- `labs/lab5/nikto/nikto-summary.json`
- `labs/lab5/sqlmap/manual-union-users.json`
- `labs/lab5/sqlmap/manual-login-bypass.json`
- `labs/lab5/sqlmap/results-manual.csv`
- `labs/lab5/sqlmap/sqlmap-summary.json`

Tool comparison:

| Tool/check | Findings | Severity breakdown | Best use case |
|---|---:|---|---|
| ZAP authenticated | 560 alert instances | 1 High, 171 Medium, 292 Low, 96 Info | Full web app crawling, passive checks, active SQLi validation with authentication |
| Nuclei-compatible template checks | 8 matches | 3 Medium, 1 Low, 4 Info | Fast header/exposure checks |
| Nikto-compatible HTTP checks | 9 findings | Header/configuration/exposure findings | Web server misconfiguration review |
| SQL injection validation | 2 injectable parameters | 2 Critical impact issues | Proving exploitability and data extraction |

Nuclei-compatible examples:

- Missing Content-Security-Policy header.
- Permissive CORS wildcard origin.
- Publicly accessible `/ftp/`, `/robots.txt`, `/sitemap.xml`, `/security.txt`.

Nikto-compatible examples:

- Missing CSP, HSTS, and Referrer-Policy headers.
- Browsable `/ftp/` directory with downloadable files.
- Permissive `Access-Control-Allow-Origin: *`.

SQL injection validation:

| Endpoint | Parameter | Evidence | Impact |
|---|---|---|---|
| `/rest/products/search` | `q` | `manual-union-users.json` contains extracted user rows | Users table data exposed through UNION SQLi |
| `/rest/user/login` | `email` | `manual-login-bypass.json` returns an admin token | Authentication bypass as `admin@juice-sh.op` |

The UNION SQLi extracted 19 Juice Shop user rows with emails and MD5 password hashes. The first extracted users include `admin@juice-sh.op`, `jim@juice-sh.op`, `bender@juice-sh.op`, `ciso@juice-sh.op`, and `support@juice-sh.op`.

## Task 3 - SAST/DAST Correlation

Summary:

| Source | Count |
|---|---:|
| SAST findings | 8 |
| ZAP authenticated alert instances | 560 |
| Nuclei-compatible matches | 8 |
| Nikto-compatible findings | 9 |
| SQL injection validated parameters | 2 |
| Combined DAST count used for comparison | 579 |

Correlated finding:

- SAST identifies SQL injection in `routes/search.ts:23`.
- ZAP confirms SQL injection dynamically on `/rest/products/search?q=apple%27`.
- SQL injection validation proves impact by extracting 19 user rows from `Users`.

Found only by SAST:

- Hardcoded RSA private key in `lib/insecurity.ts:23`.
- Weak MD5 password hashing in `lib/insecurity.ts:43`.
- Hardcoded HMAC secret in `lib/insecurity.ts:44`.
- Dangerous `eval()`/`yaml.load()` code patterns.

Found only by DAST:

- Runtime missing HTTP headers: CSP, HSTS, Referrer-Policy.
- Runtime permissive CORS behavior.
- Browsable `/ftp/` directory.
- Actual exploitability and data extraction through HTTP requests.

Why the tools differ:

- SAST sees source-code secrets, crypto choices, and dangerous APIs before deployment.
- DAST sees deployed behavior: headers, CORS, reachable routes, and exploitability.
- Using both is necessary: SAST found the vulnerable code, while DAST proved practical impact.

## Recommendations

| Priority | Issue | Recommendation |
|---|---|---|
| P0 | SQL injection in search/login flows | Replace string-built SQL with parameterized Sequelize queries |
| P0 | Hardcoded JWT private key | Move signing keys to secret storage and rotate exposed keys |
| P0 | Admin login bypass / data extraction | Add SQLi regression tests and block unsafe query construction in CI |
| P1 | MD5 password hashes | Migrate to Argon2id or bcrypt with per-user salts |
| P1 | Hardcoded HMAC secret | Move secrets to environment-backed secret management |
| P2 | Missing CSP/HSTS/Referrer-Policy | Configure Helmet/security middleware for all responses |
| P2 | Permissive CORS | Restrict allowed origins and methods |
| P2 | Browsable `/ftp/` | Remove directory listing and require access control for downloadable files |

## Reproduction

Useful commands:

```bash
bash labs/lab5/scripts/compare_zap.sh
bash labs/lab5/scripts/summarize_dast.sh
```

On this Windows host, use the bundled w64devkit bash if `bash` resolves to WSL:

```powershell
C:\Users\zhidk\w64devkit\bin\bash.exe labs/lab5/scripts/compare_zap.sh
C:\Users\zhidk\w64devkit\bin\bash.exe labs/lab5/scripts/summarize_dast.sh
```
