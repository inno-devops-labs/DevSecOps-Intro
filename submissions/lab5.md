## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~2 minutes
- Total alerts: **10**

| Severity      | Count |
|---------------|------:|
| High          | 0 |
| Medium        | 2 |
| Low           | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: ~5 minutes (spider + ajax spider + active scan)
- Total alerts: **12**

| Severity      | Count |
|---------------|------:|
| High          | 1 |
| Medium        | 4 |
| Low           | 3 |
| Informational | 4 |

### The “10–20× more” claim (Lecture 5 slide 11)

- Ratio (auth alerts / baseline alerts): **12 / 10 = 1.2×**
- Did your run match the lecture’s ratio?

  No, this is far below the claimed 10–20×. The baseline scan performed only passive scanning, while the authenticated scan added active scanning. Many Juice-Shop flaws (e.g., SQL injection) require active payloads and an authenticated session to be detectable. The baseline already caught several passive misconfiguration issues, shrinking the gap. With a longer, deeper authenticated scan the ratio would likely increase.

- Pick **two specific alerts** that only the authenticated scan found:

  1. **Alert: “SQL Injection” — High severity**  
     *Why unreachable?* The baseline used passive scanning only and never sent malicious payloads; additionally the vulnerable endpoint `/rest/products/search?q=` requires an authenticated user session to return exploitable results.

  2. **Alert: “Session Management Response Identified” — Medium severity**  
     *Why unreachable?* This alert fires when ZAP observes login/logout responses, which only appear after the authenticated user has been configured and the spider traverses authenticated pages.

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
|----------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 Injection (CI/CD) |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01 Broken Access Control |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)

If I could fix only **one** rule, I'd pick `express-sequelize-injection`.

It appears 6 times, including in live routes `login.ts` and `search.ts`. Switching to Sequelize’s built-in parameterized queries would fix all instances at once, preventing SQL injection across the entire application with minimal code change.

### False-positive sample

- **File:** `data/static/codefixes/dbSchemaChallenge_1.ts`
- **Rule:** `express-sequelize-injection`
- **Reason:** This file is part of a static code-fixes challenge used for training. It is not a deployed route and is never called by the running application; the intentionally vulnerable code is a learning exercise.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | `/rest/products/search?q=test` | `express-sequelize-injection` | `routes/search.ts:23` | High (both agree) |

### Strongest correlation deep-dive

**1. Vulnerable code** (`routes/search.ts:23`)

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR
    description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

**2. Working payload (from ZAP's authenticated scan)**

```http
GET /rest/products/search?q=' OR 1=1--
```

This returns all products, confirming blind SQL injection.

**3. Fix**

```typescript
// Replace raw query with Sequelize model + parameterized inputs
const products = await Product.findAll({
  where: {
    [Op.or]: [
      { name: { [Op.like]: `%${criteria}%` } },
      { description: { [Op.like]: `%${criteria}%` } }
    ],
    deletedAt: null
  }
});
```

**4. Why both tools caught it**

Semgrep statically flagged the dangerous string interpolation into a SQL statement. ZAP dynamically confirmed the vulnerability by sending a crafted payload and observing the application's altered response. The SAST finding pinpoints the exact line to fix; the DAST evidence proves the flaw is actually reachable and exploitable.

### Reflection

In a real PR review, I'd want the SAST finding first because it identifies the root cause in the code before deployment. The DAST evidence then proves exploitability, making the argument for a fix undeniable. Together they form the highest-confidence finding.
