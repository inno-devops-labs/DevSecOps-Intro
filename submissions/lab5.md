# Lab 5 — SAST and DAST: Reading the Code, Then Watching It Run

## Task 1

Both ZAP runs targeted Juice Shop v20.0.0. The unauthenticated passive baseline completed in ~32 seconds; the second run, using the provided authenticated plan with an active scan, completed in ~7 minutes.

| Run | High | Medium | Low | Informational | Total alert types | URLs with findings |
|---|---:|---:|---:|---:|---:|---:|
| Unauthenticated baseline | 0 | 2 | 1 | 1 | 4 | 11 |
| Authenticated plan with active scan | 2 | 4 | 3 | 4 | 13 | 23 |

The second run reported more alert types (13 vs 4) and the highest-risk findings (High vs Medium). Examples present only in its report are SQL Injection at `http://juice-shop:3000/rest/products/search?q=%27%28` and Private IP Disclosure at `http://juice-shop:3000/rest/admin/application-configuration`.

These are report-only differences: the baseline was passive, whereas the second run actively tested inputs and crawled more of the application. Neither URL is shown by these reports to require authentication, so I cannot claim that an anonymous request could not reach either one. The available evidence does not establish two findings on authenticated-only resources; that acceptance criterion remains unverified.

Alert totals are a poor comparison because the scans used different techniques and visited different URL sets; one passive alert type can cover many instances, while one active probe can reveal a more serious defect. I would report severity, the affected routes, reproducible evidence, coverage and confidence, not just the count of alert types. A pipeline whose only DAST step is `zap-baseline.py` against staging covers passive observations but can miss actively discoverable defects such as this SQL-injection finding. It should include a separately validated active and authenticated scan of appropriate test accounts and routes.

## Task 2

Semgrep scanned the Juice Shop source checked out and revealed 27 findings, 13 ERROR and 14 WARNING. The JSON contains 39 scan errors; Semgrep still reported a completed scan, and these errors limit coverage of the affected files rather than representing 39 additional findings.

| Rule ID | Findings |
|---|---:|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 |
| `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | 4 |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 |
| `yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell` | 1 |

The workflow rule `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` flags `.github/workflows/ci.yml:202`, which uses `coverallsapp/github-action@v2`. This matches Lecture 4’s advice to pin third-party actions to immutable commit SHAs

I would suppress the `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` finding at `server.ts:273` for this version. That line lists files in `/.well-known`, which currently contains public `security.txt` and CSAF metadata. The rule spots `serveIndex` but does not account for what is in the directory. I would limit the suppression to `/.well-known` and still investigate the findings for `/encryptionkeys` and `/support/logs`.

I would fix `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` first. Two of its six findings are in live routes, `routes/search.ts:23` and `routes/login.ts:34`, where user input is inserted into SQL strings. Parameterized queries would address that risk. The other four findings are in teaching examples under `data/static/codefixes/`, so I would review them separately.

## Bonus

| OWASP Top 10:2025 | ZAP finding | Semgrep finding |
|---|---|---|
| A05 Injection | SQL Injection at `GET http://juice-shop:3000/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` at `routes/search.ts:23` |

At `routes/search.ts:21–23`, the value of `req.query.q` is inserted directly into a SQL `LIKE` query. ZAP tested the same route with `q='(` and received a 500 error. That error does not prove data was extracted, but the code shows why the input is risky. I would replace the string interpolation with a parameterized query and add a test using quotes and other SQL characters.

I would put this finding first in the PR description because it affects a public route and both tools point to the same problem. The ZAP request shows how to reproduce the error, while the Semgrep result shows where to fix it.