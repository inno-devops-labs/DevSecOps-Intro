# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- Duration: ~1 min.
- Total alerts: 10
  | Severity | Count |
  |----------|------:|
  | High | 0 |
  | Medium | 2 |
  | Low | 5 |
  | Informational | 3 |

### Authenticated full scan

- Duration: ~7 min.
- Total alerts: 12
  | Severity | Count |
  |----------|------:|
  | High | 1 |
  | Medium | 4 |
  | Low | 3 |
  | Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)

- Ratio (auth alerts / baseline alerts): 1.2×
- Did your run match the lecture's ratio? (2-3 sentences)
  No, my run resulted in a ratio of 1.2×, which is drastically lower than the 10–20× claimed in the lecture. This discrepancy is expected because OWASP Juice Shop is an intentionally vulnerable application that exposes many misconfigurations (like missing security headers and CORS issues) on public pages, heavily inflating the unauthenticated baseline. In real-world enterprise applications, public-facing surfaces are usually hardened, meaning the baseline finds very little and the vast majority of vulnerabilities are hidden behind authentication.
- Pick **two specific alerts** that only the authenticated scan found. For each:
  1. Alert title + severity
  2. Why was it unreachable to the unauthenticated scan? (1 sentence)

  1.1 Private IP Disclosure (Low) \
  1.2 Why it was unreachable: This alert was triggered on the /rest/admin/application-configuration endpoint, which is strictly protected by access controls and requires a valid admin session to view, meaning the unauthenticated scan never receives the HTTP response containing the internal IP addresses.

  2.1 Session ID in URL Rewrite (Medium) \
  2.2 Why it was unreachable: This alert was found on socket.io URLs containing a sid (Session ID) parameter, which is only generated and appended to the URL by the frontend JavaScript after a user successfully logs in and establishes a persistent WebSocket/polling session.

## Task 2: SAST with Semgrep

### Semgrep severity breakdown

| Severity  | Count |
| --------- | ----: |
| ERROR     |    12 |
| WARNING   |    10 |
| INFO      |     0 |
| **Total** |    22 |

### Top 10 rules by frequency

| Rule ID                                                                                           | Count | OWASP category |
| ------------------------------------------------------------------------------------------------- | ----: | -------------- |
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection       |     6 | A03            |
| yaml.github-actions.security.run-shell-injection.run-shell-injection                              |     5 | A03            |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing |     4 | A01/A05        |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile                       |     4 | A04            |
| javascript.express.security.audit.express-open-redirect.express-open-redirect                     |     1 | A01            |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret                                |     1 | A07            |
| javascript.lang.security.audit.code-string-concat.code-string-concat                              |     1 | A03            |

### Triage shortcut (Lecture 5 slide 8)

I would prioritize fixing the express-sequelize-injection rule first. It has the highest frequency (6 findings) and targets critical backend route handlers like routes/login.ts and routes/search.ts where raw SQL queries are constructed. Refactoring these specific files to use parameterized queries or Sequelize's safe binding syntax will eliminate the most severe database compromise risk and clear multiple high-severity findings in one go.

### False-positive sample

Pick **one** finding you'd suppress as a false positive after review. Quote the file path +
rule + 1-sentence reason. (NOT generic — must reference the specific code.)

- File path: labs/lab5/semgrep/juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts
  Rule: javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
  Reason: This file is a static asset containing intentionally vulnerable code snippets served to the frontend for the application's interactive "Coding Challenges", rather than an active route handler that processes live production traffic.

## Bonus: SAST/DAST Correlation

### Correlation table

| #   | OWASP cat                                                 | ZAP alert                                                                                        | ZAP URI                                                                           | Semgrep rule                      | Semgrep file:line     | Confidence                                                                                                                                                              |
| --- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- | --------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | A03 Injection                                             | SQL Injection                                                                                    | `/rest/products/search`                                                           | `express-sequelize-injection`     | `routes/search.ts:23` | **High** (ZAP triggered a 500 error via `'(` payload; Semgrep found the exact tainted Sequelize query in the route handler)                                             |
| 2   | A03 Injection                                             | SQL Injection                                                                                    | `/rest/user/login`                                                                | `express-sequelize-injection`     | `routes/login.ts:34`  | **High** (ZAP triggered a 500 error via `'` payload on the email parameter; Semgrep flagged the identical unsafe raw SQL construction)                                  |
| 3   | A01 Broken Access Control / A05 Security Misconfiguration | Timestamp Disclosure - Unix _(leaked via `serve-index` stack trace)_ & Exposure of `/ftp/` files | `/juice-shop/node_modules/serve-index/index.js:149:39` and `/ftp/acquisitions.md` | `express-check-directory-listing` | `server.ts:269`       | **High** (ZAP proved the `serve-index` package is active and leaking internal paths/files; Semgrep found the exact server configuration enabling the directory listing) |

### Strongest correlation deep-dive

**Finding:** SQL Injection in the product search endpoint  
**OWASP:** A03:2021 – Injection | **CWE:** CWE-89

| Side     | Tool    | Evidence                                                                                                                                                                                                                                     |
| -------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **SAST** | Semgrep | Rule `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` flagged `routes/search.ts:23` — a tainted `req.query` value flows directly into a raw `sequelize.query()` call with string interpolation. |
| **DAST** | ZAP     | Sent payload `q='(` to `GET /rest/products/search` and received `HTTP 500 Internal Server Error`, confirming the backend SQL parser choked on the malformed input.                                                                           |

why:

- Both tools independently identified the same cause (unsanitized user input in a SQL query).
- Both map to the same CWE-89 and OWASP A03 category.
- Semgrep tells us where the bug lives in the source; ZAP tells us the bug is actually exploitable at runtime.
- Neither finding alone is debatable: the code pattern is unambiguously vulnerable, and the 500 error is unambiguous proof of injection. Together, they leave zero room for "won't fix" or "false positive" arguments.

---

### Reflection (2-3 sentences)

In a real PR review, I would want the SAST finding first — because PRs happen before deployment, when no running instance exists for DAST to probe. Semgrep's line-level pointer (`routes/search.ts:23`) gives the developer an immediately actionable fix during code review, which is the whole point of "shifting left." DAST evidence is ultimately more confident (it proves real exploitability), but it belongs later in the pipeline — in staging or pre-prod — once the code is actually running and can be attacked end-to-end.
