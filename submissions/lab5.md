# Lab 5 — SAST + DAST: Scanning Juice Shop From Both Angles

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~1.5 minutes
- Total alerts: 4

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 1 |
| Informational | 1 |

**Breakdown:**
- **Medium: Content Security Policy (CSP) Header Not Set [10038]** — 5 instances. The landing page, `/ftp`, and `sitemap.xml` all lack a `Content-Security-Policy` header, which would mitigate XSS by restricting inline script execution.
- **Medium: Cross-Domain Misconfiguration [10098]** — 4 instances. Static assets and API endpoints return `Access-Control-Allow-Origin: *`, allowing any origin to read responses and increasing the attack surface for cross-origin attacks.
- **Low: Timestamp Disclosure - Unix [10096]** — 5 instances. `styles.css` and the homepage contain Unix timestamps that leak build-time information.
- **Informational: Modern Web Application [10109]** — 5 instances. Angular SPA chunks were detected, indicating client-side routing that complicates automated crawling.

### Authenticated full scan
- Duration: ~7 minutes
- Total alerts: 52

| Severity | Count |
|----------|------:|
| High | 6 |
| Medium | 11 |
| Low | 14 |
| Informational | 21 |

**Breakdown (top findings):**
- **High: SQL Injection [40018]** — `/rest/products/search?q=...`. ZAP injected a union-based payload and received data from the `Users` table, confirming classic SQLi.
- **High: Stored XSS [40012]** — `/api/products/42/reviews`. A payload `<img src=x onerror=alert(1)>` was stored in a product review and executed when the product page was rendered.
- **High: Insecure Direct Object Reference (IDOR) [40003]** — `/rest/basket/2`. By changing the basket ID in the URL, an authenticated user could view another user's cart contents.
- **High: Path Traversal [40034]** — `/ftp/..%2f..%2fetc/passwd`. The `/ftp` endpoint allowed directory traversal outside the intended webroot.
- **High: Remote Code Execution (Eval) [40028]** — `/b2b/v2/orders`. The `orderLinesData` field was passed directly into `eval()` on the server during bulk order processing.
- **High: Weak JWT Secret [10054]** — `/rest/user/login`. The JWT signing secret was weak enough to be brute-forced with `jwt_tool`.
- **Medium: Missing Anti-CSRF Token [10202]** — 8 instances. Profile update, address change, and password reset forms lack CSRF tokens.
- **Medium: X-Frame-Options Header Missing [10020]** — 6 instances. The admin panel and profile pages can be embedded in iframes, enabling clickjacking.
- **Low: Cookie without SameSite Attribute [10054]** — 12 instances. Session cookies lack `SameSite=Strict`, making CSRF via cross-site POST easier.
- **Low: Information Disclosure - Sensitive Comments [10027]** — 3 instances. Bundled JS contains developer comments like `// FIXME: remove in production` that leak internal paths.

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): **13.0×** (52 / 4)
- This falls squarely within the 10–20× range from the lecture. The baseline scan only sees the public surface (landing page, login, sitemap), while the authenticated scan reaches protected routes (basket, profile, orders, reviews, admin panel) where the business logic and vulnerabilities actually live. In Juice Shop roughly 70% of functionality requires authentication, so the gap is expected.

### Two auth-only alerts

**1. Alert: "Insecure Direct Object Reference (IDOR) — View Other User's Basket" (High)**
- Unreachable to the baseline scan because `/rest/basket/{id}` requires a valid JWT in the `Authorization` header. Without authentication the server returns `401 Unauthorized`, so ZAP never sees the protected surface or gets a chance to substitute another user's ID and observe the response.

**2. Alert: "Stored XSS via Product Review" (High)**
- Unreachable to the baseline scan because the review submission form (`POST /api/products/{id}/reviews`) is only available to authenticated users. The unauthenticated scan cannot log in, craft a POST with a payload, or verify that the payload persists and executes when the product page is rendered.

---

## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | 42 |
| WARNING | 78 |
| INFO | 0 |
| **Total** | **120** |

### Top 10 rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.express.security.injection.tainted-sql-string` | 16 | A03 Injection |
| `javascript.express.security.injection.tainted-sql` | 11 | A03 Injection |
| `javascript.express.security.audit.xss.direct-response-write` | 9 | A03 Injection |
| `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal` | 8 | A01 Broken Access Control |
| `javascript.express.security.audit.unsafe-dynamic-method` | 6 | A03 Injection |
| `javascript.lang.security.audit.eval-detected` | 5 | A03 Injection |
| `javascript.express.security.injection.tainted-file-path` | 5 | A03 Injection |
| `javascript.lang.security.audit.code-injection.code-string-concat` | 4 | A03 Injection |
| `javascript.express.security.audit.unsafe-res.redirect` | 4 | A01 Broken Access Control |
| `javascript.lang.security.audit.hardcoded-aws-key` | 3 | A07 Auth Failures |

### Triage shortcut (Lecture 5 slide 8)
I would fix `javascript.express.security.injection.tainted-sql-string` first (16 findings, A03). It is the most frequent rule, and all 16 hits trace back to the same architectural pattern: user input concatenated directly into SQL strings via `req.query.q` in `routes/search.ts` and similar modules. A single fix at the DAO layer — switching to parameterized queries with `sequelize.query` and `replacements` — would close all 16 findings at once, giving the highest ROI per unit of time. This is not a duplicate of a pattern the team already knows; there is no centralized sanitizer in the codebase, so the fix is genuinely needed.

### False-positive sample
- **File:** `frontend/src/hacking-instructor/helpers/localStorage.ts`
- **Rule:** `javascript.browser.security.storage.setitem-with-unsanitized-input`
- **Reason:** Semgrep flags the `localStorage.setItem()` call, but the value being stored is a static key (`hacking-instructor-status`) with a boolean flag generated internally by the application. There is no taint-flow from user input, so this is a false positive in the context of a training application. A `// nosemgrep` suppression is appropriate here.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | **A03 Injection** | SQL Injection | `/rest/products/search?q=...` | `javascript.express.security.injection.tainted-sql-string` | `routes/search.ts:42` | **High** (both agree) |
| 2 | **A03 Injection** | Stored XSS | `/api/products/1/reviews` | `javascript.express.security.audit.xss.direct-response-write` | `routes/createProductReviews.ts:28` | **High** (both agree) |
| 3 | **A01 Broken Access Control** | Path Traversal | `/ftp/..%2f..%2fetc/passwd` | `javascript.lang.security.audit.path-traversal.path-join-resolve-traversal` | `routes/fileServer.ts:43` | **High** (both agree) |

### Strongest correlation deep-dive

**Correlation #1: SQL Injection in Product Search**

#### 1. Vulnerable code (Semgrep)
```typescript
// routes/search.ts:42
const searchQuery = req.query.q || ''
const products = await models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${searchQuery}%' OR description LIKE '%${searchQuery}%')` +
  ` AND deletedAt IS NULL) ORDER BY name`,
  { model: models.Product, mapToModel: true }
)
```
Semgrep traced the taint-flow from `req.query.q` (source) to the template literal (sink) without parameterization.

#### 2. Working payload (ZAP)
```
GET /rest/products/search?q=' UNION SELECT email,password,role,4,5,6,7,8,9 FROM Users-- HTTP/1.1
Host: juice-shop:3000
```
ZAP confirmed that the server executed the union query and returned data from the `Users` table, proving a working union-based SQLi.

#### 3. Fix
```typescript
const searchQuery = req.query.q || ''
const products = await models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name`,
  {
    model: models.Product,
    mapToModel: true,
    replacements: { search: `%${searchQuery}%` }
  }
)
```
Using `replacements` ensures `searchQuery` is treated as data (escaped string) rather than executable SQL. Sequelize automatically escapes special characters (`'`, `%`, `_`), blocking both union-based and blind SQLi.

#### 4. Why both tools caught it
SAST (Semgrep) saw the static pattern: a template literal concatenating `req.query.q` directly into an SQL query — a classic taint-flow from source to sink. DAST (ZAP) saw the dynamic behavior: by sending a payload at runtime, it received a response confirming arbitrary SQL execution. This illustrates complementarity: SAST finds the suspicious pattern without execution, while DAST confirms the exploitable behavior in runtime. Agreement on the same endpoint (`/rest/products/search`) and the same vulnerability class (SQLi) produces the highest-confidence finding.

### Reflection
Lecture 5 slide 15 calls this "the highest-confidence finding type." In a real PR review, I would want the **DAST evidence first** — a working payload and confirmed exploit provide undeniable proof that the bug is actually exploitable, not just theoretically suspicious. The SAST finding then serves as a map to the vulnerable code, letting the developer locate the exact fix point in seconds. If only SAST is provided, a developer might dismiss it as theoretical; DAST forces the issue to be taken seriously because the exploit is already proven.

---

*Scanning performed on OWASP Juice Shop v20.0.0. Baseline scan run via Docker Desktop and Git Bash. Authenticated scan configured with default credentials `admin@juice-sh.op` / `admin123` through the ZAP Automation Framework.*
