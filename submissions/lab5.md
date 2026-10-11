# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- Duration: ~3 minutes
- Total alerts: **10**

| Severity      |  Count |
| ------------- | -----: |
| High          |      0 |
| Medium        |      2 |
| Low           |      5 |
| Informational |      3 |
| **Total**     | **10** |

### Authenticated full scan

- Duration: ~9 minutes
- Total alerts: **12**

| Severity      |  Count |
| ------------- | -----: |
| High          |      1 |
| Medium        |      4 |
| Low           |      3 |
| Informational |      4 |
| **Total**     | **12** |

### The "10–20× more" claim (Lecture 5 slide 11)

- Ratio (auth alerts / baseline alerts): **1.2×** (12 ÷ 10)
- Did your run match the lecture's ratio?

  No. The 10–20× claim assumes deep crawling of auth-only routes (cart, profile, admin). Our baseline was a quick passive scan with few findings, and while the auth run added more, Juice Shop exposes many vulnerabilities without login anyway — so the gap stayed modest. A more aggressive auth crawl or non-admin user scan would likely push the ratio higher.

- Auth-only alerts:

1. **SQL Injection** (**high** severity) — The auth scan unlocked protected API surfaces and user-only functionality that the unauth crawl skipped entirely. That expanded reach let ZAP spot SQL injection paths hidden behind the login wall.
2. **Session ID in URL Rewrite** (**medium** severity) — It stayed hidden until ZAP had a valid session; the vulnerable endpoint and its session-bound traffic don't exist in an unauthenticated context.

---

## Task 2: SAST with Semgrep

### Semgrep severity breakdown

| Severity  |  Count |
| --------- | -----: |
| ERROR     |     12 |
| WARNING   |     10 |
| INFO      |      0 |
| **Total** | **22** |

### Top rules by frequency

| Rule ID                                                                                             | Count | OWASP category             |
| --------------------------------------------------------------------------------------------------- | ----: | -------------------------- |
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`       |     6 | A03 Injection              |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection`                              |     5 | A03 / CI pipeline          |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` |     4 | A05 Misconfiguration       |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile`                       |     4 | A01 Broken Access Control  |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect`                     |     1 | A01 Broken Access Control  |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret`                                |     1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat`                              |     1 | A03 Injection              |

### Triage shortcut (Lecture 5 slide 8)

First rule to fix: `express-sequelize-injection` with 6 hits. It's the same unsafe pattern — raw queries via string interpolation — repeated across multiple routes. One central fix (parameterized queries instead of template literals) wipes out the whole cluster and plugs SQLi on user-facing endpoints in one shot.

### False-positive sample

- File path: `labs/lab5/semgrep/juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts`
- Rule: `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
- Reason: This file is inside data/static/codefixes/, which stores fix-it challenge examples for learning purposes. This isn't a production route handler, so the finding is pedagogic, not a real runtime threat.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| #   | OWASP cat     | ZAP alert                          | ZAP URI                       | Semgrep rule                               | Semgrep file:line      | Confidence        |
| --- | ------------- | ---------------------------------- | ----------------------------- | ------------------------------------------ | ---------------------- | ----------------- |
| 1   | A03 Injection | SQL Injection (High)               | `/rest/products/search?q=...` | `express-sequelize-injection`              | `routes/search.ts:~18` | High (both agree) |
| 2   | A01           | Session ID in URL Rewrite (Medium) | authenticated routes          | `express-open-redirect` / session handling | various `routes/*.ts`  | Medium            |

### Strongest correlation deep-dive

**Vulnerable code (Semgrep):**

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
);
```

**Working payload (ZAP):**

```
GET /rest/products/search?q='))+UNION+SELECT+sql,2,3,4,5,6,7,8,9+FROM+sqlite_schema+--
Parameter: q
```

**Proposed fix:**

Use Sequelize `replacements` (or ORM query builder) instead of embedding `criteria` in a template literal:

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`,
  {
    replacements: { criteria: `%${criteria}%` },
    type: models.sequelize.QueryTypes.SELECT,
  }
);
```

**Why both tools caught it:**

Semgrep caught the static pattern — user input fed straight into `sequelize.query`. ZAP then confirmed it's actually reachable and injectable at runtime under an authenticated session. That's the highest-confidence finding type per the lecture 5.

### Reflection

In a real PR review I'd start with **DAST** evidence — it shows real runtime impact and justifies urgency. Then I'd pull the **SAST** finding to locate the exact vulnerable line and apply the fix. The two reports complement each other perfectly.
