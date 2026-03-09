# Lab 5 Submission — SAST & DAST Security Analysis (OWASP Juice Shop)

## Task 1 — Static Application Security Testing (Semgrep)

### 1. SAST Tool Effectiveness
Semgrep detected **25 findings** in total from `p/security-audit` + `p/owasp-top-ten` rulesets:
- **7 `ERROR`** findings
- **18 `WARNING`** findings

Coverage from `semgrep-results.json`:
- **Files scanned:** 1014
- **Findings:** 25

What Semgrep detected well in this run:
- SQL injection patterns in Sequelize queries
- Dangerous code execution patterns (`eval` data flow)
- Hardcoded secret pattern (JWT secret)
- Open redirect / untrusted redirect patterns
- Risky file-serving patterns and template/script injection sinks

### 2. Critical Vulnerability Analysis (Top 5)

| # | Vulnerability Type | File Path | Line | Semgrep Severity |
|---|---|---|---:|---|
| 1 | SQL Injection (tainted Sequelize query) | `/src/routes/login.ts` | 34 | `ERROR` |
| 2 | SQL Injection (tainted Sequelize query) | `/src/routes/search.ts` | 23 | `ERROR` |
| 3 | User input flow to `eval` (code execution risk) | `/src/routes/userProfile.ts` | 62 | `ERROR` |
| 4 | Hardcoded JWT secret | `/src/lib/insecurity.ts` | 56 | `WARNING` |
| 5 | Open redirect / untrusted redirect target | `/src/routes/redirect.ts` | 19 | `WARNING` |

Notes:
- The highest-impact class in SAST output is injection/code execution (`ERROR`).
- The JWT secret and redirect issues are `WARNING` in Semgrep output, but still security-relevant.

---

## Task 2 — Dynamic Application Security Testing (Multi-Tool)

### 1. Authenticated vs Unauthenticated ZAP Scanning
From `labs/lab5/analysis/zap-comparison.txt`:

- **Unauthenticated scan:**
  - Total alerts: **12**
  - Medium: **2**, Low: **6**, Info: **4**, High: **0**
  - Unique URLs with findings: **16**

- **Authenticated scan:**
  - Total alerts: **11**
  - Medium: **4**, Low: **4**, Info: **3**, High: **0**
  - Unique URLs with findings: **17**

Examples of authenticated/admin-related endpoints discovered in authenticated results:
- `http://localhost:3000/rest/admin/application-configuration`
- `http://localhost:3000/rest/user/login`
- Session/socket endpoints (multiple `socket.io` URLs with session IDs)

Why authenticated scanning matters:
- It reached privileged/internal attack surface (admin + session-related routes) that is not fully visible anonymously.
- Even with slightly fewer total alert types, authenticated mode found **more medium-risk issues** and **more unique URLs with findings**.

### 2. Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|---|---:|---|---|
| ZAP (authenticated) | 11 alert types | 0 High, 4 Medium, 4 Low, 3 Info | Full web app assessment, auth flows, runtime security headers/session issues |
| Nuclei | 1 match | 1 Info (`swagger-api`) | Fast template-driven checks for known exposures/CVEs/patterns |
| Nikto | 83 entries (`+` lines) | No native severity rating in output | Web server/config hygiene, risky files/paths, header and content exposure checks |
| SQLmap | 2 unique SQLi points across CSV results | SQLi confirmed (`B` and `BT` techniques) | Deep, targeted SQL injection testing and data extraction validation |

### 3. Tool-Specific Strengths
- **ZAP**
  - Strength: broad runtime coverage, authentication-aware crawling/scanning.
  - Example findings: `Content Security Policy (CSP) Header Not Set`, `Session ID in URL Rewrite`, `Missing Anti-clickjacking Header`.

- **Nuclei**
  - Strength: very fast signature/template-based exposure detection.
  - Example finding: `Public Swagger API - Detect` at `/api-docs/swagger.yaml`.

- **Nikto**
  - Strength: server misconfiguration and sensitive file/path discovery.
  - Example findings: missing `X-XSS-Protection`, interesting resources (`/ftp/`, `/public/`), many backup/cert-like path probes.

- **SQLmap**
  - Strength: deep SQLi exploitation and validation of real DB impact.
  - Example findings: SQLi on `/rest/products/search` (boolean-based) and `/rest/user/login` JSON parameter (boolean/time-based), with database extraction evidence in logs.

---

## Task 3 — SAST/DAST Correlation and Security Assessment

### 1. SAST vs DAST Comparison

Total findings comparison:
- **SAST (Semgrep):** 25
- **Combined DAST (ZAP + Nuclei + Nikto + SQLmap):** 97
  - ZAP 11 + Nuclei 1 + Nikto 83 + SQLmap 2 (unique SQLi points)

Vulnerability types found **only by SAST** in this lab:
- Hardcoded secret pattern (`jwt-hardcode`)
- User-controlled flow to `eval` (code-level execution sink)
- Source-level insecure redirect/file-serving patterns before exploitation

Vulnerability types found **only by DAST** in this lab:
- Missing/weak runtime security headers (CSP, anti-clickjacking, X-Content-Type)
- Runtime cross-domain/CORS-related misconfiguration signals
- Exposed runtime content/endpoints (e.g., public Swagger API, accessible `ftp`/server paths)

Why results differ:
- **SAST** inspects source code and catches implementation flaws even if they are hard to trigger at runtime.
- **DAST** validates the live deployed behavior (headers, routes, auth/session behavior, exposed artifacts).
- Together they provide complementary coverage; neither alone is complete.

