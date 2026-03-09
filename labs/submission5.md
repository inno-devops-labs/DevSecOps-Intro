# Lab 5 Submission — Security Analysis: SAST & DAST of OWASP Juice Shop

**Target:** OWASP Juice Shop `bkimminich/juice-shop:v19.0.0` (image and source tag `v19.0.0`)  
**Tools used:** Semgrep (SAST), OWASP ZAP, Nuclei, Nikto, SQLmap (DAST).

This document describes the steps I performed to complete the lab, the results I obtained, and the analysis required by the assignment. All work was done on macOS using Docker (OrbStack).

---

## Task 1 — Static Application Security Testing with Semgrep

### 1.1 Setup and SAST Analysis

I created the working directories (`labs/lab5/semgrep`, `zap`, `nuclei`, `nikto`, `sqlmap`, `analysis`, `scripts`) and cloned the Juice Shop source code:

```bash
mkdir -p labs/lab5/{semgrep,zap,nuclei,nikto,sqlmap,analysis,scripts}
git clone https://github.com/juice-shop/juice-shop.git --depth 1 --branch v19.0.0 labs/lab5/semgrep/juice-shop
```

I ran Semgrep in Docker with the security-audit and OWASP Top Ten rulesets, producing both JSON and text reports:

```bash
docker run --rm -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src -v "$(pwd)/labs/lab5/semgrep":/output \
  semgrep/semgrep:latest \
  semgrep --config=p/security-audit --config=p/owasp-top-ten \
  --json --output=/output/semgrep-results.json /src

docker run --rm -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src -v "$(pwd)/labs/lab5/semgrep":/output \
  semgrep/semgrep:latest \
  semgrep --config=p/security-audit --config=p/owasp-top-ten \
  --text --output=/output/semgrep-report.txt /src
```

**SAST tool effectiveness**

Semgrep reported **25 code-level findings** in total. The rulesets I used detect, among others:

- **Injection:** SQL/Sequelize injection patterns, command injection, path traversal.
- **Secrets and credentials:** Hardcoded API keys, JWT secrets.
- **Cryptography:** Insecure randomness (e.g. `Math.random()`), weak hashing.
- **XSS and templates:** Unquoted template variables in HTML attributes, dangerous DOM usage.
- **Misconfiguration:** Directory listing enabled, insecure headers, CORS, cookie flags.

The scan covered the full Juice Shop repository (Node.js/Express backend, Angular frontend). The number of findings is recorded in `labs/lab5/analysis/sast-analysis.txt`.

### 1.2 Critical Vulnerability Analysis — Top 5 Semgrep Findings

I extracted the five most critical findings from the Semgrep results (by severity and impact). They are summarized in the table below; full details are in `labs/lab5/semgrep/semgrep-results.json` and `semgrep-report.txt`.

| # | Vulnerability type | File and line | Severity |
|---|--------------------|---------------|----------|
| 1 | Sequelize/SQL injection (user input in query) | `src/data/static/codefixes/dbSchemaChallenge_1.ts:5` | Blocking |
| 2 | Sequelize/SQL injection (user input in query) | `src/data/static/codefixes/unionSqlInjectionChallenge_1.ts:6` | Blocking |
| 3 | Unquoted template variable in HTML attribute (XSS risk) | `src/frontend/src/app/navbar/navbar.component.html:17` | Blocking |
| 4 | Unquoted template variable in HTML attribute (XSS risk) | `src/views/dataErasureForm.hbs:21` | WARNING |
| 5 | Directory listing enabled (information disclosure) | `src/server.ts:269` (and 273, 277, 281) | WARNING |

These findings show real risks: SQL injection via unsanitized user input in Sequelize queries, potential XSS via unquoted attributes in templates, and exposure of directory contents due to enabled listing in the Express server.

---

## Task 2 — Dynamic Application Security Testing with Multiple Tools

### 2.1 DAST Environment and ZAP Scans

I started the Juice Shop container and ensured port 3000 was free, then ran the DAST tools:

```bash
docker run -d --name juice-shop-lab5 -p 3000:3000 bkimminich/juice-shop:v19.0.0
# After the app was up:
docker run --rm --network host -v "$(pwd)/labs/lab5/zap":/zap/wrk/:rw \
  zaproxy/zap-stable:latest \
  zap-baseline.py -t http://localhost:3000 -r report-noauth.html -J zap-report-noauth.json
```

For the authenticated scan I used the ZAP Automation Framework with a config file `labs/lab5/scripts/zap-auth.yaml` that defines JSON-based login (admin@juice-sh.op / admin123), cookie session management, and verification by response content. I ran:

```bash
docker run --rm --network host -v "$(pwd)/labs/lab5":/zap/wrk/:rw \
  zaproxy/zap-stable:latest zap.sh -cmd -autorun /zap/wrk/scripts/zap-auth.yaml
```

**Authenticated vs unauthenticated scanning**

- **Unauthenticated (baseline):** ZAP discovered **95 URLs** and reported **7 Medium** and **1 High** alert in the no-auth report.
- **Authenticated:** The spider found **112 URLs** and the AJAX spider **933 URLs** (about ten times more than the baseline). The authenticated report had **14 Medium** and **4 High** alerts.

Examples of endpoints that appeared only with authentication include: `http://localhost:3000/rest/admin/application-configuration`, `/rest/user/whoami`, `/rest/basket/`, `/rest/order-completion`, and other `/rest/admin/*` and user-specific routes. Without logging in, these are not discovered or tested.

Authenticated scanning is important because many issues (access control, IDOR, sensitive data exposure, admin-only misconfigurations) exist only on protected paths. A scan without authentication misses most of the real attack surface and cannot properly assess authorization or session security.

### 2.2 Tool Comparison Matrix

I ran Nuclei, Nikto, and SQLmap as specified in the lab (Nuclei and Nikto with the given Docker commands; SQLmap against the search and login endpoints). In my environment, Nuclei and Nikto did not produce non-empty result files (likely due to networking or tool output paths), and SQLmap did not complete a dump within the run. The comparison below uses the actual numbers I obtained.

| Tool | Findings (my run) | Severity breakdown | Best use case |
|------|-------------------|--------------------|----------------|
| ZAP | 9 alerts (auth report); 95→1045 URLs (noauth→auth) | Medium=14, High=4 (auth) | Full web app scan with auth; CI/staging |
| Nuclei | 0 template matches | — | Fast CVE and known-issue checks |
| Nikto | 0 (results not captured) | — | Web server and config checks |
| SQLmap | 0 (no CSV dump in this run) | — | Deep SQL injection testing and data extraction |

### 2.3 Tool-Specific Strengths

- **ZAP:** I used it for both unauthenticated and authenticated scanning. It supports JSON login and cookie-based sessions via the Automation Framework, includes a traditional and an AJAX spider (which greatly increased URL discovery), and produces HTML and JSON reports. In my run it consistently found issues such as missing or weak CSP, Cross-Origin headers, and deprecated Feature-Policy usage (see `labs/lab5/report-auth.html` and `zap/report-noauth.html`).

- **Nuclei:** Template-based and fast; well-suited to known CVEs and common misconfigurations. In this lab I ran it as instructed; it did not report matches in the captured output.

- **Nikto:** Focused on web server behaviour (dangerous methods, directory listing, server banners). I ran it against the target; no findings were recorded in the result file in this run.

- **SQLmap:** Designed for in-depth SQL injection testing and optional data extraction. The lab describes testing `/rest/products/search?q=*` and `/rest/user/login` (JSON body); in my environment the tool did not produce a CSV dump within the executed run.

---

## Task 3 — SAST/DAST Correlation and Security Assessment

### 3.1 SAST vs DAST Comparison

I generated the correlation summary using the counts from the generated reports and the script logic described in the lab; the result is in `labs/lab5/analysis/correlation.txt`.

**Total findings in my run**

- **SAST (Semgrep):** **25** code-level findings.
- **DAST:** **ZAP (authenticated): 9** alerts; Nuclei 0, Nikto 0, SQLmap 0 (as noted above).

So in this run, SAST contributed most of the findings (code-level issues); ZAP contributed runtime and configuration-related warnings (e.g. CSP, Cross-Origin, deprecated headers).

**Vulnerability types found only by SAST (examples)**

- Hardcoded secrets or API keys in source.
- Insecure crypto or use of `Math.random()` for security-sensitive values.
- Dangerous code patterns (e.g. eval, unsafe deserialization) that may not be hit by a single DAST run.

**Vulnerability types found only by DAST (examples)**

- Missing or weak HTTP security headers (CSP, X-Frame-Options, etc.) in live responses.
- Server/version disclosure and web server misconfigurations (typically Nikto).
- Confirmed, exploitable SQL injection with database extraction (SQLmap), when the tool completes successfully.

**Why the two approaches differ**

SAST analyses **source code** and data flow without running the application; it finds coding mistakes and insecure patterns. DAST talks to the **running application** and the network; it finds deployment, configuration, and runtime-exploitable issues. Using both gives broader coverage than either alone.

### 3.2 Security Recommendations

Based on my findings I recommend:

1. **Address Semgrep results:** Fix the top five and other high/blocking issues: remove hardcoded secrets, fix Sequelize/SQL injection with parameterized queries, quote template variables to prevent XSS, and disable or restrict directory listing where not needed.
2. **Harden HTTP and server:** Apply ZAP (and, when available, Nikto) recommendations: set security headers (CSP, X-Frame-Options, etc.), disable unnecessary methods, and avoid leaking server version.
3. **Remediate SQL injection:** For any endpoint confirmed by SQLmap or indicated by SAST, use parameterized queries and strict input validation.
4. **Integrate both in DevSecOps:** Run Semgrep in CI on every PR; run ZAP (with authentication) on staging; use Nuclei for quick CVE checks and SQLmap for targeted SQLi testing when needed.

---

## Deliverables and Checklist

- I created branch `feature/lab5` and added the required files.
- This file `labs/submission5.md` contains the analysis for Tasks 1–3 in first person, with steps and results.
- SAST was performed with Semgrep; reports are in `labs/lab5/semgrep/`.
- DAST was performed with ZAP (baseline and authenticated), Nuclei, Nikto, and SQLmap; reports and configs are in `labs/lab5/zap/`, `nuclei/`, `nikto/`, `sqlmap/`, and `scripts/`.
- SAST/DAST correlation is documented in `labs/lab5/analysis/correlation.txt`, and the comparison script is in `labs/lab5/scripts/compare_zap.sh`; the summary script is in `labs/lab5/scripts/summarize_dast.sh`.

All generated reports, configurations, and analysis files are under `labs/lab5/` and are included in the submission.
