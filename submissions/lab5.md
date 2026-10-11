# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: 2 minutes
- Total alerts: 10
| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: 10 minutes
- Total alerts: 12
| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 1.2x
- Did your run match the lecture's ratio? (2-3 sentences): No, my authenticated scan only found 1.2× more alerts than the unauthenticated scan, which is significantly lower than the lecture's claim of 10–20× more issues. This discrepancy is likely because different application in lecture or different config.

- Pick **two specific alerts** that only the authenticated scan found. For each:
#### Alert 1: SQL Injection
  1. SQL Injection (pluginid: 40018); Severity: High (riskcode: 3)
  2. Why was it unreachable to the unauthenticated scan? (1 sentence) This vulnerability exists in the login endpoint (`/rest/user/login`) and product search (`/rest/products/search?q=...`), both of which require authentication to access or are only triggered when authenticated session cookies are present.

#### Alert 1:  Session ID in URL Rewrite
  1. Session ID in URL Rewrite; Severity: Medium (riskcode: 2)
  2. Why was it unreachable to the unauthenticated scan? (1 sentence) The session ID (`sid` parameter) is only generated and transmitted in WebSocket/polling requests after authentication, so the unauthenticated scan never sees these session tokens in URL parameters.

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
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03: Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03: Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05: Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A05: Security Misconfiguration |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A04: Insecure Design |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02: Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03: Injection |

**Total unique rules: 7** (only 7 rule types detected across 22 findings)

### Triage shortcut (Lecture 5 slide 8)
Looking at the top 10 — which **one rule** would you fix first if you had time for only one?

**Rule to fix first**: `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` (6 findings, ERROR severity)


**Why?** (2-3 sentences. Likely answer: the highest-frequency rule that's not a duplicate
of patterns the team already knows about; one fix at the module level closes many findings.)
This rule detects SQL injection vulnerabilities in Sequelize ORM queries, which is the highest-frequency (6 findings) **ERROR severity** issue. SQL injection remains one of the OWASP Top 10's most critical vulnerabilities (A03: Injection) and could lead to data theft or complete database compromise. Fixing this one rule would eliminate the highest-risk attack vector with the most impact (6 findings).

### False-positive sample
Pick **one** finding you'd suppress as a false positive after review. Quote the file path +
rule + 1-sentence reason. (NOT generic — must reference the specific code.)

**File path**: `labs/lab5/semgrep/juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts`

**Code**:
```typescript
5┆ models.sequelize.query("SELECT * FROM Products WHERE ((name LIKE '%"+criteria+"%' OR description LIKE '%"+criteria+"%') AND deletedAt IS NULL) ORDER BY name")
```

**Rule**: `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`

**Reason**: This finding is in a challenge/learning code directory (`data/static/codefixes/`), not production code — it's intentionally vulnerable code meant to teach developers how to fix SQL injection, so it should be suppressed in the security pipeline as it's not a real application risk.

## Bonus: SAST/DAST Correlation

### Correlation table

| Finding | SAST (Semgrep) | DAST (ZAP) | Confidence |
|---------|----------------|------------|------------|
| SQL Injection on `/rest/products/search` | ✅ `routes/search.ts` line 23: `models.sequelize.query(\`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name\`)` | ✅ `http://juice-shop:3000/rest/products/search?q=%27%28` — HTTP/1.1 500 Internal Server Error | 🔥 **High** |
| SQL Injection on `/rest/user/login` | ✅ `routes/login.ts` line 34: `models.sequelize.query(\`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL\`, { model: UserModel, plain: true })` | ✅ `http://juice-shop:3000/rest/user/login` — HTTP/1.1 500 Internal Server Error | 🔥 **High** |

### Strongest correlation deep-dive

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03: Injection | SQL Injection | `/rest/products/search?q=%27%28` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/search.ts:23` | 🔥 High |
| 2 | A03: Injection | SQL Injection | `/rest/user/login` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `routes/login.ts:34` | 🔥 High |

### B.3: The fix — proposed remediation

**Strongest correlation**: SQL Injection on `/rest/products/search` (A03: Injection)

#### Vulnerable code (SAST)
**File**: `routes/search.ts:23`
```typescript
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

#### Working payload (DAST evidence)
**ZAP-detected URI**: `http://juice-shop:3000/rest/products/search?q=%27%28`
- This payload (`'(`) triggers a SQL syntax error that results in HTTP/1.1 500 Internal Server Error, confirming the injection point is unparameterized.

#### The fix
Replace the dynamic string interpolation with Sequelize's built-in parameterization:
```typescript
// VULNERABLE (current)
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)

// FIXED
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`,
  {
    replacements: { criteria: `%${criteria}%` },
    type: QueryTypes.SELECT
  }
)
```
Alternatively, use Sequelize's `Op.like` operator to avoid raw SQL entirely:
```typescript
models.Product.findAll({
  where: {
    [Op.or]: [
      { name: { [Op.like]: `%${criteria}%` } },
      { description: { [Op.like]: `%${criteria}%` } }
    ],
    deletedAt: null
  },
  order: [['name', 'ASC']]
})
```

#### Why both tools caught it
**SAST** (Semgrep) flagged the unparameterized template literal directly in source code as a taint flow. **DAST** (ZAP) triggered the actual error by injecting special characters into the query parameter, demonstrating the vulnerability is real and exploitable at runtime. This makes it a high-confidence finding — both static analysis and dynamic testing agree on the same root cause.

### Reflection (2-3 sentences)
In a real PR review, I would want the **DAST evidence first**, then the **SAST finding**. The DAST proof (the HTTP 500 error triggered by a simple payload) is irrefutable and demonstrates immediate business impact; the Semgrep finding provides the root cause and fix direction. Together they form the strongest case for prioritization: "This is exploitable in production right now (DAST), and here's the exact line to fix (SAST)."
Lecture 5 slide 15 calls this "the highest-confidence finding type." In a real PR review,
which of these two would you want first — the SAST finding or the DAST evidence — and why?