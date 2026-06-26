# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- **Duration:** ~2 minutes
- **Total unique alert types:** 10
- **URLs spidered:** 158

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

**Alerts found:**
- `[Medium]` Content Security Policy (CSP) Header Not Set (5 instances)
- `[Medium]` Cross-Domain Misconfiguration (5 instances)
- `[Low]` Cross-Origin-Embedder-Policy Header Missing or Invalid (5 instances)
- `[Low]` Cross-Origin-Opener-Policy Header Missing or Invalid (5 instances)
- `[Low]` Dangerous JS Functions (1 instance)
- `[Low]` Deprecated Feature Policy Header Set (5 instances)
- `[Low]` Timestamp Disclosure - Unix (5 instances)
- `[Info]` Modern Web Application (5 instances)
- `[Info]` Storable and Cacheable Content (1 instance)
- `[Info]` Storable but Non-Cacheable Content (5 instances)

### Authenticated full scan

- **Duration:** ~5 minutes
- **Total unique alert types:** 12
- **URLs spidered:** 93 (traditional) + 447 (Ajax)

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

**Alerts found:**
- `[High]` SQL Injection (2 instances)
- `[Medium]` Content Security Policy (CSP) Header Not Set (5 instances)
- `[Medium]` Cross-Domain Misconfiguration (5 instances)
- `[Medium]` Missing Anti-clickjacking Header (3 instances)
- `[Medium]` Session ID in URL Rewrite (5 instances)
- `[Low]` Private IP Disclosure (1 instance)
- `[Low]` Timestamp Disclosure - Unix (5 instances)
- `[Low]` X-Content-Type-Options Header Missing (5 instances)
- `[Info]` Authentication Request Identified (1 instance)
- `[Info]` Modern Web Application (5 instances)
- `[Info]` Session Management Response Identified (2 instances)
- `[Info]` User Agent Fuzzer (3 instances)

### The "10–20x more" claim (Lecture 5 slide 11)

- **Ratio (auth alert types / baseline alert types):** 1.2x (12 / 10)
- **Did your run match the lecture's ratio?** No — the ratio was significantly lower than the 10–20x claim. However, the authenticated scan did find the only **High-severity** vulnerability (SQL Injection) that the unauthenticated scan completely missed. The lower ratio is likely because Juice Shop is intentionally designed with a large unauthenticated attack surface (158 URLs spidered without auth), which reduces the relative gap between the two scans. A longer authenticated scan with deeper active scanning would likely find more authenticated-only issues.

**Two specific alerts only the authenticated scan found:**

1. **SQL Injection (High)** — The unauthenticated spider cannot reach authenticated endpoints like `/rest/user/login` (POST) or meaningfully interact with the `q` parameter on `/rest/products/search`. The authenticated scan, running with valid session credentials, was able to fuzz these protected endpoints and detect SQL injection via error-based detection (HTTP 500 responses to `'(` and `'` payloads).

2. **Missing Anti-clickjacking Header (Medium)** — This finding applies to authenticated pages that include sensitive UI (account dashboard, password change). The unauthenticated spider only sees the public login/registration pages, so it cannot evaluate clickjacking protections on authenticated routes.

---

## Task 2: SAST with Semgrep

### Scan configuration
- **Rulesets:** `p/owasp-top-ten`, `p/javascript`, `p/secrets`
- **Target:** Juice Shop v20.0.0 source code
- **Severity filter:** ERROR, WARNING
- **Result:** 22 findings (12 ERROR + 10 WARNING)

### Semgrep severity breakdown

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| **Total** | **22** |

### Top 10 rules by frequency

| # | Rule ID | Count | OWASP Category |
|---|---------|------:|----------------|
| 1 | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03: Injection |
| 2 | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03: Injection |
| 3 | `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05: Security Misconfiguration |
| 4 | `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01: Broken Access Control |
| 5 | `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01: Broken Access Control |
| 6 | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A05: Security Misconfiguration |
| 7 | `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03: Injection |

*Note: Only 7 unique rules triggered. The top 2 rules account for 50% of all findings.*

### Triage shortcut (Lecture 5 slide 8)

I would fix **`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`** first if I had time for only one rule. It has the highest frequency (6 findings) and represents SQL injection vulnerabilities — the most severe class of issues in the scan. All 6 findings trace to the same root cause: unsafe string concatenation in Sequelize queries. A single fix — introducing parameterized queries at the database access layer — would eliminate all 6 findings at once, making it the highest-impact remediation.

### False-positive sample

**Finding to suppress:**
- **File:** `data/static/codefixes/dbSchemaChallenge_1.ts`
- **Rule:** `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
- **Reason:** This file is an intentional vulnerable code sample used for the "dbSchemaChallenge" CTF challenge. It is not production code — it exists specifically to teach SQL injection concepts. The `// vuln-code-snippet` comment explicitly marks it as educational material. Suppressing this finding with `# nosemgrep` is appropriate because fixing it would break the challenge's learning objective.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03: Injection | SQL Injection | `/rest/products/search?q='(` | `express-sequelize-injection` | `routes/search.ts:23` | **High** (both agree on same endpoint) |
| 2 | A03: Injection | SQL Injection | `/rest/user/login` (POST, `email='`) | `express-sequelize-injection` | `routes/login.ts:34` | **High** (both agree on same endpoint) |

### Strongest correlation deep-dive (#1 — `/rest/products/search`)

**Vulnerable code (from Semgrep):**

```typescript
// routes/search.ts:23
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

The `criteria` variable is derived directly from `req.query.q` without sanitization:
```typescript
let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
```

**Working payload (from ZAP):**
```
'(
```
ZAP injected `'(` as the `q` parameter and observed an HTTP 500 Internal Server Error, confirming the SQL syntax was broken by the unescaped single quote — a classic error-based SQL injection detection.

**The fix:**

```typescript
// Fixed code using parameterized query
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
  {
    replacements: { criteria: `%${criteria}%` },
    type: QueryTypes.SELECT
  }
)
```

**Why both tools caught it:**

- **SAST** detected this because Semgrep's `express-sequelize-injection` rule pattern-matches the unsafe template-string concatenation (`'...${userInput}...'`) inside `sequelize.query()` — a known dangerous API pattern.
- **DAST** caught it because ZAP's active scanner fuzzed the `q` query parameter with SQL meta-characters (single quote `'` and open parenthesis `(`) and observed that the application responded with HTTP 500 Internal Server Error, confirming the database query was syntactically broken.
- The vulnerability is discoverable from both angles because the unsafe code pattern (static analysis) directly enables the runtime exploit (dynamic testing). Both tools agree: this is the highest-confidence finding type.

### Reflection

Lecture 5 slide 15 calls correlation findings "the highest-confidence finding type." In a real PR review, I would want the **SAST finding first** — it pinpoints the exact line of vulnerable code (`routes/search.ts:23`) and explains *why* it's dangerous (user input flows directly into a SQL query without parameterization). The DAST evidence then validates that the vulnerability is actually exploitable at runtime. SAST drives the fix; DAST confirms the fix worked after deployment.


## Raw Results

| Result file | Location |
|-------------|----------|
| ZAP Baseline JSON | `labs/lab5/results/baseline-report.json` |
| ZAP Authenticated JSON | `labs/lab5/zap/zap-report-auth.json` |
| ZAP Authenticated HTML | `labs/lab5/zap/report-auth.html` |
| Semgrep JSON | `labs/lab5/results/semgrep.json` |
| ZAP Comparison | `labs/lab5/analysis/zap-comparison.txt` |


PR checklist:
```text
- [x] Task 1 — ZAP baseline + auth + ratio analysis
- [x] Task 2 — Semgrep top-10 + triage shortcut + false positive
- [x] Bonus — Correlation table with 2 confirmed cross-tool findings
```
