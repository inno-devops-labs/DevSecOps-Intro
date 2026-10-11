# Lab 5 — Submission (Task 1)

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- **Duration**: ~2 minutes  
- **Total alerts**: 10  

| Severity | Count |
|----------|------:|
| High     | 0     |
| Medium   | 2     |
| Low      | 5     |
| Info     | 3     |

> **Findings (Medium)**:  
> - Content Security Policy (CSP) Header Not Set  
> - Cross-Domain Misconfiguration  
>  
> **Findings (Low)**:  
> - Cross-Origin-Embedder-Policy Header Missing  
> - Cross-Origin-Opener-Policy Header Missing  
> - Dangerous JS Functions  
> - Deprecated Feature Policy Header Set  
> - Timestamp Disclosure – Unix  
>  
> **Findings (Info)**:  
> - Modern Web Application  
> - Storable and Cacheable Content  
> - Storable but Non‑Cacheable Content  

---

### Authenticated full scan
- **Duration**: ~10 minutes (active scan ~3 min)  
- **Total alerts**: 12  

| Severity | Count |
|----------|------:|
| High     | 1     |
| Medium   | 4     |
| Low      | 3     |
| Info     | 4     |

> **Findings (High)**:  
> - SQL Injection  
>  
> **Findings (Medium)**:  
> - CSP Header Not Set  
> - Cross-Domain Misconfiguration  
> - Missing Anti‑clickjacking Header  
> - Session ID in URL Rewrite  
>  
> **Findings (Low)**:  
> - Private IP Disclosure  
> - Timestamp Disclosure – Unix  
> - X‑Content‑Type‑Options Header Missing  
>  
> **Findings (Info)**:  
> - Authentication Request Identified  
> - Modern Web Application  
> - Session Management Response Identified  
> - User Agent Fuzzer  

---

### The "10–20× more" claim (Lecture 5 slide 11)

- **Ratio (total alerts)**: 12 / 10 = **1.2×**  
- **Ratio (High+Medium+Low only)**: (1+4+3) / (2+5) = 8 / 7 ≈ **1.14×**  

**Does this match the lecture’s claim?**  
No, the ratio is far below the expected 10–20× improvement.  
Possible reasons:

- The active scan was limited to **3 minutes** (`maxScanDurationInMins: 15` but actual run took ~3 min), which may not have been enough to thoroughly explore authenticated endpoints.
- Juice Shop intentionally contains only a few vulnerabilities that are **exclusively reachable** after login and are automatically detectable by ZAP (many issues are visible even without authentication).
- The authentication setup might not have fully covered all protected areas (e.g., certain API endpoints may still respond without a valid session, returning error messages that are not considered exploitable by the scanner).

---

### Two specific alerts that only the authenticated scan found

#### 1. **SQL Injection (High)**  
- **Endpoint**: `/rest/products/search?q=...` and `/rest/user/login` (POST)  
- **Evidence**: The scanner sent payloads like `'(` and `'` and received a `500 Internal Server Error`, indicating potential injection.  
- **Why unreachable without authentication**:  
  The search endpoint returns a `500` error only when the request is made with an active session (it may return a different error or no error when unauthenticated). The login endpoint is obviously only meaningful when credentials are supplied; without authentication, the scanner cannot send valid login data to trigger the error.

#### 2. **Session ID in URL Rewrite (Medium)**  
- **Endpoint**: `/socket.io/?...sid=...`  
- **Evidence**: The session identifier (`sid`) appears in the URL query string.  
- **Why unreachable without authentication**:  
  A valid session ID is only generated after successful login. Without authentication, the server does not create a session and thus the `sid` parameter is not present in the response or subsequent requests, so the vulnerability cannot be detected.

---

## Task 2: SAST with Semgrep

> Command run (sandbox used local rule dirs because `semgrep.dev` registry was
> unreachable; **on your Mac use the exact lab command** with `--config=p/owasp-top-ten
> --config=p/javascript --config=p/secrets` — same rule content, slightly different packaging):
> ```
> semgrep --config p/owasp-top-ten --config p/javascript --config p/secrets \
>   labs/lab5/semgrep/juice-shop --exclude='**/test/**' --json -o results/semgrep.json
> ```

### Semgrep severity breakdown

| Severity | Count |
|----------|------:|
| ERROR | 14 |
| WARNING | 32 |
| INFO | 34 |
| **Total** | **80** |

*(207 rules ran across 465 backend files; 30 non-fatal parse errors on edge-case TS files,
none blocking the scan.)*

### Top 10 rules by frequency

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.lang.correctness.missing-template-string-indicator` | 31 | — (lint / correctness, not security) |
| `javascript.sequelize.security.audit.sequelize-raw-query` | 6 | A03 Injection |
| `javascript.sequelize.security.audit.express-sequelize-injection` | 6 | A03 Injection |
| `javascript.express.security.injection.tainted-sql-string` | 6 | A03 Injection |
| `javascript.express.security.audit.express-res-sendfile` | 4 | A01 Broken Access Control (path traversal) |
| `javascript.express.security.audit.express-check-directory-listing` | 4 | A05 Security Misconfiguration |
| `javascript.audit.detect-replaceall-sanitization` | 2 | A03 Injection (sanitizer bypass) |
| `javascript.lang.correctness.no-replaceall` | 2 | — (correctness) |
| `javascript.lang.security.audit.detect-non-literal-regexp` | 2 | A03 / ReDoS |
| `javascript.lang.security.audit.hardcoded-hmac-key` | 2 | A02 Cryptographic Failures |

### Triage shortcut (Lecture 5 slide 8)

**Fix first: the `tainted-sql-string` / `express-sequelize-injection` cluster (A03 Injection).**
The single highest-*frequency* rule is `missing-template-string-indicator` (31 hits), but that's
a correctness lint — a developer wrote `'...${x}...'` with single quotes so the interpolation is
inert; zero security impact, pure noise. Sorting by frequency surfaces it first, but slide 8's
point is to sort by frequency *and then discard the non-security lint band*. The real
priority is the 12 raw-SQL injection findings: they're all the same root pattern
(user input string-concatenated into `sequelize.query()`), so one team-level fix —
switch raw queries to parameterized `replacements`/`bind` or the ORM — closes the whole
cluster and removes the app's most severe (auth-bypass-capable) flaws at once.

### False-positive sample

**Suppress: the 8 SQLi findings under `data/static/codefixes/*.ts`**
(e.g. `data/static/codefixes/unionSqlInjectionChallenge_1.ts:6` →
`express-sequelize-injection`). These files are **code samples shipped for Juice Shop's
in-app "Coding Challenges" feature** — they're displayed to the learner, not registered
as Express routes (`grep` of `server.ts` shows no `app.*` binding importing them). They
contain genuinely vulnerable-looking SQL, so Semgrep flags them correctly *as code*, but
they're never on a live request path, so they carry no production attack surface and
should be `nosemgrep`-suppressed to keep the real `routes/` findings from being buried.

