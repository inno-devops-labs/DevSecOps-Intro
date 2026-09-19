# Lab 5 — SAST + DAST: Scanning Juice Shop From Both Angles

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: 2 minutes 49 seconds
- Total alerts: 10

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: 13 minutes 36 seconds
- Total alerts: 12

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)

- Ratio (auth alerts / baseline alerts): **1.2×**

- Did your run match the lecture's ratio?

No. My authenticated scan produced only 12 alert types compared to 10 in the unauthenticated scan, resulting in a ratio of 1.2× instead of the 10–20× mentioned in the lecture. This difference is likely due to the current Juice Shop/ZAP versions and the scan configuration, which exposed only a small number of additional authenticated endpoints.

- Pick **two specific alerts** that only the authenticated scan found

1. **SQL Injection** — **High**
   - This vulnerability was only reachable after authentication because the affected functionality is available only to logged-in users.

2. **Authentication Request Identified** — **Informational**
   - This request is visible only after a successful login because it is part of the authenticated user workflow.

## Task 2: SAST with Semgrep

### Semgrep severity breakdown

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | 22 |

### Top 10 rules by frequency

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | 6 | A03:2021 – Injection |
| yaml.github-actions.security.run-shell-injection.run-shell-injection | 5 | A08:2021 – Software and Data Integrity Failures |
| javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing | 4 | A05:2021 – Security Misconfiguration |
| javascript.express.security.audit.express-res-sendfile.express-res-sendfile | 4 | A05:2021 – Security Misconfiguration |
| javascript.express.security.audit.express-open-redirect.express-open-redirect | 1 | A01:2021 – Broken Access Control |
| javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | 1 | A02:2021 – Cryptographic Failures |
| javascript.lang.security.audit.code-string-concat.code-string-concat | 1 | A03:2021 – Injection |

### Triage shortcut (Lecture 5 slide 8)

If I could fix only one rule, I would prioritize `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`. It has the highest number of findings and represents a SQL injection risk, which is one of the most critical OWASP vulnerabilities. Fixing the affected database access pattern would eliminate multiple findings at once and significantly reduce the application's attack surface.

### False-positive sample

**File:** `.github/workflows/update-challenges-www.yml`  
**Rule:** `yaml.github-actions.security.run-shell-injection.run-shell-injection`

**Reason:** I would suppress this finding after review because the workflow is an internal GitHub Actions automation script used by project maintainers. Although Semgrep flags the use of GitHub context variables inside a `run:` step, the workflow is not part of the deployed Juice Shop application and does not represent a runtime vulnerability affecting end users.

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03:2021 – Injection                 | SQL Injection                                | `/rest/products/search?q='(` | `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`       | `routes/search.ts`     | High       |
| 2 | A05:2021 – Security Misconfiguration | Content Security Policy (CSP) Header Not Set | `/`                          | `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | `server.ts`            | Medium     |
| 3 | A05:2021 – Security Misconfiguration | Information Disclosure                       | `/ftp/coupons_2013.md.bak`   | `javascript.express.security.audit.express-res-sendfile.express-res-sendfile`                       | `routes/fileServer.ts` | Medium     |
| 4 | A01:2021 – Broken Access Control | Information Disclosure | `/rest/admin/application-configuration` | `javascript.express.security.audit.express-open-redirect.express-open-redirect` | `routes/redirect.ts` | Low |
| 5 | A02:2021 – Cryptographic Failures | Authentication endpoint analysis | `/rest/user/login` | `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | `lib/insecurity.ts` | Medium |

### Strongest correlation deep-dive

**OWASP category:** A03:2021 – Injection

**ZAP evidence**
- **Alert:** SQL Injection
- **URI:** `/rest/products/search?q='(`

**Semgrep evidence**
- **Rule:** `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
- **Source:** `routes/search.ts`

**Why this correlation is strong**

Both tools point to the same search functionality. ZAP shows that the endpoint can be attacked during runtime, and Semgrep shows where the unsafe database query is written in the source code. Because both tools report the same issue, this is a high-confidence finding.

### Reflection (2–3 sentences)

I would like to see the SAST finding first because it tells me exactly where the problem is in the source code. The DAST result is also important because it proves that the vulnerability can actually be reached in the running application. When both tools report the same issue, I can be much more confident that it is a real vulnerability.