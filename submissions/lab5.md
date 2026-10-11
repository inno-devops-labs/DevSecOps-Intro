# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: under 2 minutes (passive scan only)
- Total alerts: 10

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: approx 11 minutes (spider 0:18 + spiderAjax 6:11 + activeScan 4:05 + report ~0:01).
  Note: maxScanDurationInMins was reduced from the lab default of 10 to 4 to keep the
  active-scan phase from running indefinitely on this machine; this was a deliberate
  time-management choice, not a default value.
- Total alerts: 12

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10-20x more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 12 / 10 = 1.2x
- This run did NOT match the lecture's 10-20x ratio. The most likely reason is the
  reduced `maxScanDurationInMins` (4 instead of 10) — the active scan got cut off
  partway through probing the 687 URLs that spiderAjax found, so many authenticated
  routes were discovered by the crawler but never actually attacked before the timer
  ran out. The lecture's ratio likely assumes a full, uninterrupted active scan. A
  second contributing factor: `passiveScan-config` caps `maxAlertsPerRule` at 10,
  which limits how many alert instances get counted per rule regardless of how many
  URLs are actually affected — this caps the ceiling on both scans similarly, but
  compresses the gap between them.

Two alerts found only by the authenticated scan:

1. **SQL Injection** (High risk, Low confidence) — found at `/rest/products/search?q=`
   (param `q`) and `/rest/user/login` (param `email`). This was unreachable to the
   unauthenticated baseline scan because baseline mode only passively observes traffic
   from a normal crawl — it never sends attack payloads. SQL Injection requires ZAP's
   *active* scan, which only runs in the authenticated full-scan job, to actually
   inject probe strings into the `q` and `email` parameters.

2. **Authentication Request Identified** — flagged because ZAP observed and logged
   an actual login POST to `/rest/user/login` during the Automation Framework's
   authentication step. The unauthenticated baseline scan never logs in at all, so
   there's no login request for this passive-scan rule to ever detect.

## Task 2: SAST with Semgrep

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
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A03 Injection (CI/CD) |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A01 Broken Access Control |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A01 Broken Access Control |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01 Broken Access Control |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A02 Cryptographic Failures |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03 Injection (eval) |

Note: only 7 distinct rules fired across the 22 findings, so this is the complete
list rather than a top-10 cut.

### Triage shortcut (Lecture 5 slide 8)
The highest-frequency rule (express-sequelize-injection, 6 findings) is the one to
fix first, but not purely because of frequency. Looking at the actual findings, all
6 are the same root pattern: raw user input (`criteria`, `req.body.email`,
`req.body.password`) gets string-interpolated directly into a `sequelize.query()`
call across `routes/search.ts`, `routes/login.ts`, and several `data/static/codefixes/`
files. This is the same vulnerability class ZAP found dynamically at
`/rest/products/search?q=` and `/rest/user/login` in Task 1 — meaning a single fix
pattern (switching to Sequelize's parameterized `replacements`/bind-parameter syntax)
closes 6 SAST findings AND the DAST-confirmed SQL injection at the same time. That's
a much higher-leverage fix than the hardcoded-jwt-secret finding, which is high-impact
but isolated to one line.

### False-positive sample
File: `server.ts`, lines 269-277 (rule:
`javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing`).
The source has inline comments marking these exact lines as
`// vuln-code-snippet vuln-line directoryListingChallenge` — Juice Shop intentionally
enables directory listing on `/ftp` and `/encryptionkeys` as the entire point of a
named training challenge, not an accidental misconfiguration. I would suppress this
finding (not because the rule is technically wrong — directory listing genuinely is
enabled — but because in this specific intentionally-vulnerable training app, the
finding doesn't represent something to remediate).

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP category | ZAP alert     | ZAP URI                    | Semgrep rule                                                                                  | Semgrep file:line  | Confidence                                                |
| - | -------------- | ------------- | -------------------------- | --------------------------------------------------------------------------------------------- | ------------------ | --------------------------------------------------------- |
| 1 | A03 Injection  | SQL Injection | `/rest/products/search?q=` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/search.ts` | High (both tools identify the same SQL injection pattern) |
| 2 | A03 Injection  | SQL Injection | `/rest/user/login`         | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/login.ts`  | High (same endpoint flagged statically and dynamically)   |

### Strongest correlation deep-dive

**Vulnerable code (Semgrep)**

```ts
sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${req.body.password}'`
)
```

Semgrep reports this because user-controlled input is concatenated directly into a raw SQL query, creating an SQL injection vulnerability.

**Working payload (ZAP)**

Endpoint:

```text
POST /rest/user/login
```

Parameter:

```text
email
```

ZAP's active scan reported **SQL Injection (High risk, Low confidence)** after injecting SQL payloads into the `email` parameter of the login request. The scan also reported SQL Injection on:

```text
GET /rest/products/search?q=
```

through the `q` query parameter.

**Proposed fix**

Replace string interpolation with parameterized queries:

```ts
sequelize.query(
  "SELECT * FROM Users WHERE email = :email AND password = :password",
  {
    replacements: {
      email: req.body.email,
      password: req.body.password
    }
  }
)
```

The same approach should be applied to the product search endpoint by binding the `q` parameter instead of concatenating it into the SQL statement.

**Why both tools caught it**

Semgrep detected the vulnerability statically by tracing tainted user input flowing into `sequelize.query()`. ZAP independently confirmed the issue by sending SQL injection payloads to the running application and identifying behavior consistent with an injectable endpoint. Since both SAST and DAST report the same vulnerability, this represents a high-confidence finding.

### Reflection

In a real pull request review, I would prioritize the DAST evidence because it demonstrates that the vulnerability is actually reachable and exploitable in the deployed application. The corresponding SAST finding is equally valuable during remediation because it points directly to the vulnerable source code, making the fix straightforward. Together they provide both exploitability evidence and precise implementation guidance.
