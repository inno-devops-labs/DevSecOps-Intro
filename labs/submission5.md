# Lab 5 — SAST & DAST of OWASP Juice Shop

> Target: `bkimminich/juice-shop:v19.0.0`
> SAST: **Semgrep** (source clone, v19.0.0). DAST: **ZAP**, **Nuclei**, **Nikto**, **SQLmap**.
> All tools run as pinned Docker images from the project root.

> **Environment note:** host port `3000` was already in use by another service
> (`langfuse`), so Juice Shop was published on **`localhost:3001`** and every DAST
> tool was pointed there instead of `:3000`. No other deviation from the lab commands.

---

## Results at a Glance

| Phase | Tool | Findings |
|-------|------|---------:|
| SAST | Semgrep | **26** (8 ERROR, 18 WARNING) |
| DAST | ZAP (full scan) | **87 instances / 12 unique alert types** (22 Medium, 42 Low, 23 Info) |
| DAST | Nuclei | **22** (1 Medium, 21 Info) |
| DAST | Nikto | **14** |
| DAST | SQLmap | **SQL injection confirmed** (boolean + time-based blind, SQLite) |

Raw evidence under `labs/lab5/{semgrep,zap,nuclei,nikto,sqlmap,analysis}/`.

> **Scope note on ZAP:** the ZAP *full* scan (spider + AJAX spider + active scan)
> is very slow against a heavy SPA like Juice Shop. The spider/AJAX-spider phases
> completed (100%) and the active scan reached ~24% before I stopped it and
> exported the alerts found so far directly from the ZAP API
> (`zap-report.json` + `zap-alerts-partial.json`). The 87 alerts below are real,
> confirmed findings; a full active scan would mainly add active-injection
> alerts on top of these passive/early-active results.

---

## Task 1 — SAST with Semgrep

Ran `p/security-audit` + `p/owasp-top-ten` over the cloned source. **26 findings**
(8 ERROR / 18 WARNING).

### SAST Tool Effectiveness
Semgrep is fast (~35 s for the whole repo), runs entirely offline against source,
and produces precise `file:line` + rule-ID output. Its pattern rules map cleanly
to OWASP categories (injection, XSS, open redirect, hardcoded secrets). It sees
**code paths that never get exercised at runtime** (e.g. challenge fixture files),
which is both a strength (coverage) and a source of noise (intentionally
vulnerable demo snippets).

### 5 Key SAST Findings

| # | Severity | Rule | Location | Issue |
|---|----------|------|----------|-------|
| 1 | ERROR | `express-sequelize-injection` | `routes/search.ts:23` | SQL injection — user input concatenated into a Sequelize raw query |
| 2 | ERROR | `express-sequelize-injection` | `routes/login.ts:34` | SQL injection in the login query (classic auth bypass) |
| 3 | ERROR | `run-shell-injection` | `.github/workflows/update-challenges-ebook.yml:21` | Command injection via untrusted input in a CI workflow |
| 4 | WARNING | `hardcoded-jwt-secret` | `lib/insecurity.ts:56` | Hardcoded JWT signing secret — forge-able tokens |
| 5 | WARNING | `express-open-redirect` | `routes/redirect.ts:19` | Open redirect from an unvalidated `to` parameter |

Other notable: `express-res-sendfile` path-traversal patterns in
`fileServer.ts`/`keyServer.ts`/`logfileServer.ts`, and `unknown-value-with-script-tag`
XSS sinks in `videoHandler.ts`.

---

## Task 2 — DAST with Multiple Tools

### Tool Comparison

| Tool | Strength in practice | What it found here |
|------|----------------------|--------------------|
| **ZAP** | Broadest web-app coverage; passive + active; full HTTP context | 12 alert types / 87 instances — CSP missing, CORS misconfig, header issues, info disclosure |
| **Nuclei** | Fast, template-driven detection/fingerprinting | 22 — exposed Prometheus `/metrics` (Medium), missing security headers, Swagger API, `security.txt`, tech fingerprints |
| **Nikto** | Web-server misconfig & path probing | 14 — exposed `/ftp/`, `/public/`, inode/ETag leak, permissive CORS (`*`), uncommon headers |
| **SQLmap** | Deep, targeted injection exploitation | **Confirmed SQLi** on `?q=` + identified backend as SQLite |

### One Significant Finding per Tool

- **ZAP — Content Security Policy (CSP) Header Not Set (Medium, 11 instances).**
  No CSP across the app, so an injected script has no browser-side mitigation —
  directly amplifies the XSS sinks Semgrep flagged.
- **ZAP/Nikto — Cross-Domain Misconfiguration / `Access-Control-Allow-Origin: *`
  (Medium, 11 instances).** Wildcard CORS lets any origin read responses;
  combined with token-bearing endpoints this enables cross-site data theft.
- **Nuclei — Prometheus metrics exposed at `/metrics` (Medium).** Unauthenticated
  internal telemetry/information disclosure.
- **Nikto — `/ftp/` directory reachable (HTTP 200, listed in robots.txt).**
  Juice Shop's file-server directory is browsable — sensitive-file exposure /
  path-traversal surface.
- **SQLmap — Boolean- and time-based blind SQLi on `GET q`.**
  Payload `q=apple%' AND 5078=5078 AND 'GiYb%'='GiYb`; backend confirmed SQLite.
  Fully exploitable database injection.

---

## Task 3 — SAST/DAST Correlation & Security Assessment

### Where the approaches agree (high-confidence, fix first)

| Vulnerability | SAST (Semgrep) | DAST | Verdict |
|---------------|----------------|------|---------|
| **SQL injection** | `express-sequelize-injection` in `search.ts:23` / `login.ts:34` | **SQLmap exploited** `?q=` | Confirmed end-to-end — static *and* dynamic proof. Top priority. |
| **Missing security headers / XSS exposure** | XSS sinks (`videoHandler.ts`, `chatbot.ts`) | ZAP/Nuclei: CSP not set, header gaps | Code has the sink, runtime lacks the mitigation. |
| **Open redirect** | `express-open-redirect` `redirect.ts:19` | ZAP redirect/info alerts | Both surfaces present. |

### SAST vs DAST — unique discoveries

- **Only SAST found:** the **hardcoded JWT secret** (`lib/insecurity.ts:56`) and
  the **CI workflow command injection** — neither is visible from outside the
  running app. (The JWT secret also lines up with the private-key/JWT secrets
  Trivy flagged in Lab 4.)
- **Only DAST found:** **runtime/deployment** issues — wildcard CORS, missing CSP,
  exposed `/ftp/` and `/metrics`, ETag inode leak — none of which exist in source
  code; they emerge from configuration and live HTTP behaviour. SQLmap further
  *proved* exploitability that SAST could only suspect.

**Why both are needed:** SAST is shift-left, offline, and pinpoints the exact
vulnerable line (great for PR gates), but over-reports on unreachable code and
can't confirm exploitability. DAST validates real exploitability and catches
config/deployment flaws SAST is blind to, but needs a running app and gives no
line numbers. Their *overlap* (SQLi here) is the strongest possible signal.

### Integrated DevSecOps Recommendations

1. **Pre-commit / PR:** Semgrep `p/security-audit` + `p/owasp-top-ten` as a
   required check — block on ERROR-level (injection, secrets).
2. **Secrets:** add a dedicated secret scan (the JWT secret shouldn't reach a PR).
3. **Staging gate:** ZAP baseline scan on every deploy; periodic ZAP *full* scan +
   Nuclei in the nightly pipeline.
4. **Targeted:** run SQLmap against parameters that SAST/DAST flag as injection
   candidates (here: `?q=`) before release.
5. **Triage by correlation:** prioritise findings confirmed by *both* SAST and
   DAST (SQLi), then DAST-confirmed exploitable issues, then SAST-only code smells.
6. **Fix the systemic gaps:** set a strict CSP, lock down CORS, parameterise all
   DB queries, and move secrets to a vault — these close whole finding classes at once.

---

## Appendix — Commands & Environment

- Target started: `docker run -d --name juice-shop-lab5 -p 3001:3000 bkimminich/juice-shop:v19.0.0`
- Images: `semgrep/semgrep:latest`, `zaproxy/zap-stable:latest` (ZAP 2.17.0),
  `projectdiscovery/nuclei:latest`, `frapsoft/nikto:latest`, `parrotsec/sqlmap:latest`.
- ZAP alerts exported from the live ZAP API (`/OTHER/core/other/jsonreport/` and
  `/JSON/alert/view/alerts/`) after stopping the long-running active scan.
- Analysis summaries: `labs/lab5/analysis/{sast-analysis,dast-analysis,correlation}.txt`.
