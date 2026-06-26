# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- Duration: **2 minutes** (121 s)
- Total alerts: **10**

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan

- Duration: **5 minutes** (318 s)
- Total alerts: **12**

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)

- Ratio (auth alerts / baseline alerts): **1.2×** (12 / 10)

- My results did not reach the 10–20× increase mentioned in the lecture. Juice Shop already exposes much of its functionality without authentication, so the baseline crawl was able to cover a large portion of the application. Even so, the authenticated scan explored additional authenticated functionality and discovered several new alert types, including a High severity SQL Injection issue that the baseline scan never identified.

- **Auth-only alert 1:** **SQL Injection** (High) on `/rest/products/search?q=…` — although the endpoint itself is publicly accessible, the authenticated active scan exercised it with SQL injection payloads during deeper testing, while the baseline scan did not verify it as an exploitable SQL Injection vulnerability.

- **Auth-only alert 2:** **Private IP Disclosure** (Low) on `/rest/admin/application-configuration` — this response is only available after authenticating as an administrator, so the unauthenticated baseline scan never reached the endpoint or observed the exposed internal address.

---

## Task 2: SAST with Semgrep

### Semgrep severity breakdown

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | **22** |

### Top 10 rules by frequency

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01 Broken Access Control |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)

I would prioritize fixing **`express-sequelize-injection`** because it appears more often than any other production-relevant rule and is directly related to OWASP A03 Injection. Replacing the vulnerable query pattern with parameterized Sequelize queries would eliminate several SQL injection findings across multiple request handlers with a single remediation approach.

### False-positive sample

- **File:** `labs/lab5/semgrep/juice-shop/data/static/codefixes/unionSqlInjectionChallenge_1.ts:6`
- **Rule:** `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
- **Reason:** This file contains a deliberately vulnerable code example used as part of the Juice Shop training challenges. Since it is educational content rather than executable application logic, I would treat this finding as a false positive for remediation purposes.


## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q='(` | `express-sequelize-injection` | `routes/search.ts:23` | High (both agree) |
| 2 | A03 Injection | SQL Injection | `/rest/user/login` (param: `email`) | `express-sequelize-injection` | `routes/login.ts:34` | High (both agree) |

### Strongest correlation deep-dive

**Vulnerable code** (`routes/search.ts:23`):

```typescript
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

**Working payload** (from ZAP auth report):

```
GET /rest/products/search?q='(
Attack: '(
Evidence: HTTP/1.1 500 Internal Server Error
```

**Fix:**

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`,
  { replacements: { criteria: `%${criteria}%` } }
)
```

**Why both tools caught it:**

Semgrep reported this issue because it detected user-controlled input flowing directly into a raw Sequelize SQL query during static analysis. ZAP confirmed the same weakness at runtime by sending a malicious payload to the endpoint and observing a database error, demonstrating that the vulnerability was actually exploitable.

### Reflection (2–3 sentences)

Lecture 5 slide 15 describes this type of result as the highest-confidence finding because both static and dynamic analysis independently identify the same vulnerability. In a real pull request review, I would first look at the DAST evidence since it confirms that the issue can be reproduced in the running application. After that, I would rely on the SAST result to quickly locate the affected source code and implement an appropriate fix.
