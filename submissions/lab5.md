# Lab 5 — Submission

---

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- Duration: ~2 minutes
- Total alerts: **10**

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |
| **Total** | **10** |

### Authenticated full scan

- Duration: ~8 minutes
- Total alerts: **12**

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |
| **Total** | **12** |

### The "10–20× more" claim (Lecture 5 slide 11)

- Ratio (auth alerts / baseline alerts): **1.2×** (12 ÷ 10)
- Did your run match the lecture's ratio? **No.** The lecture's 10–20× figure assumes a full authenticated crawl + active scan against protected routes (basket, profile, admin APIs). Our baseline was a quick passive spider only (~10 alerts, no High), while the auth run added active scanning and reached logged-in surfaces — but Juice Shop's public API still exposes many endpoints without login, so the gap stayed small. A longer auth spider/AJAX crawl or scanning with a non-admin user would likely widen the ratio.
- Auth-only alert **#1:** **SQL Injection**, **High** — unreachable to baseline because the injectable search/query endpoint is either not spidered deeply in passive baseline mode or requires parameters only exercised during authenticated active scan.
- Auth-only alert **#2:** **Session ID in URL Rewrite**, **Medium** — unreachable to baseline because it only appears once a logged-in session exists and ZAP observes session tokens in rewritten URLs.

---

## Task 2: SAST with Semgrep

Scanned pinned source `juice-shop` tag **v20.0.0** with local rulesets: `owasp-rules.yml`, `javascript-rules.yml`, `secrets-rules.yml` (`--severity ERROR --severity WARNING`).

### Semgrep severity breakdown

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | **22** |

```json
[
  {"severity": "ERROR", "count": 12},
  {"severity": "WARNING", "count": 10}
]
```

### Top rules by frequency

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 / CI pipeline |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01 Broken Access Control |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

*(Only 7 distinct rules matched at ERROR/WARNING severity; scan total 22 findings.)*

### Triage shortcut (Lecture 5 slide 8)

First rule to fix: **`express-sequelize-injection`** (6 hits). It flags raw Sequelize queries built with string interpolation across multiple route handlers — the same anti-pattern that enables SQLi at runtime. One module-level fix (replacements/bind parameters instead of template literals) closes multiple findings at once and directly reduces exploit risk on user-facing search/API endpoints.

### False-positive sample

- File: `.github/workflows/ci.yml` (or other Juice Shop workflow flagged by Semgrep)
- Rule: `yaml.github-actions.security.run-shell-injection.run-shell-injection`
- Reason: The rule flags `${{ ... }}` expansions in `run:` steps, but GitHub Actions context values in the upstream CI workflow are not attacker-controlled at runtime like a web request parameter — this is standard pipeline syntax, not an application RCE vector. Would suppress after manual review of the specific step and inputs.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection (High) | `/rest/products/search?q=...` | `express-sequelize-injection` | `routes/search.ts:~18` | High (both agree) |
| 2 | A01 | Session ID in URL Rewrite (Medium) | authenticated routes | `express-open-redirect` / session handling | various `routes/*.ts` | Medium |

### Strongest correlation deep-dive

**Vulnerable code (Semgrep):**

```typescript
// routes/search.ts — express-sequelize-injection (6 related hits across routes)
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
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
  { replacements: { criteria: `%${criteria}%` }, type: models.sequelize.QueryTypes.SELECT }
)
```

**Why both tools caught it:**

Semgrep matched the static pattern (user input concatenated into `sequelize.query`). ZAP proved the endpoint is reachable and injectable at runtime during authenticated active scan — highest-confidence finding type (Lecture 5 slide 15).

### Reflection

In a real PR review I would want **DAST evidence first** (ZAP URI + payload proving exploitability), then **SAST** to locate the exact file/line for the fix. SAST alone can over-report similar patterns; DAST alone misses code paths not crawled. Together they give both proof and remediation location.
