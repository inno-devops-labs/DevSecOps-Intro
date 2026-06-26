# Lab 5 — Submission

> SAST data is from a **real Semgrep 1.168.0 run against `juice-shop@v20.0.0`** (backend
> only: `frontend/`, `test/`, `node_modules/` excluded). DAST baseline is from a real ZAP
> baseline run; the authenticated active scan could not complete on Apple Silicon (arm64) —
> documented honestly with log evidence in Task 1.

---

## Task 1: DAST with OWASP ZAP

> Run these on your Mac (Docker + ghcr.io reachable there). The numbers come from
> `summarize_dast.sh` / `compare_zap.sh` against the two JSON reports.

### Baseline (unauthenticated) scan
- Duration: ~1 min
- Total alerts: 10 (8 WARN-NEW rule types; FAIL-NEW: 0)

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

*(Medium: CSP Header Not Set [10038], Cross-Domain Misconfiguration [10098]. No High-risk
alerts on the unauthenticated surface — expected, since the dangerous endpoints sit behind login.)*

### Authenticated full scan — environment limitation (Apple Silicon / arm64)

The authenticated scan was attempted repeatedly via the ZAP Automation Framework
(`zap-auth.yaml`) but **could not be completed on this machine** (Apple Silicon, macOS,
Docker Desktop, `os.arch: aarch64`). The traditional spider authenticated correctly and
enumerated the site (88–93 in-scope URLs from the point of view of user `admin`), but the
**active scan never produced alerts** — it consistently exits or is terminated before
writing findings. The output is a valid-but-empty report (`auth-report.json`, 308 bytes,
`"alerts": []`).

Three distinct, reproducible failure modes were diagnosed from `zap.log`:

1. **AJAX spider crash (Crawljax + headless Firefox on arm64).** During `spiderAjax`:
   `UnreachableBrowserException: Error communicating with the remote browser. It may have
   died`, followed by repeated `NoSuchSessionException: Session ID is null`. The embedded
   Firefox/geckodriver in the ZAP image is unstable under emulated arm64, killing the whole
   plan (exit 2) before the report job.
2. **Active scan terminates on large URL sets.** With the AJAX spider enabled (674 URLs
   discovered) the active scan logs `Job activeScan terminated` — aborted under
   `maxRuleDurationInMins` pressure across hundreds of nodes, with no alerts written.
3. **Re-authentication storm (header-based session-mgmt variant).** When session management
   was switched to header-based JWT (`Authorization: Bearer {%json:authentication.token%}`)
   to correctly carry Juice Shop's token, `verification: poll` re-triggered login on nearly
   every request (`Authenticating user: admin` repeated across all scan threads), and the
   active scan stalled inside `PathTraversalScanRule` / `SourceCodeDisclosureCve20121823ScanRule`.

These are known ZAP-on-arm64 active-scan issues, independent of the lab plumbing
(confirmed **not OOM**: `OOMKilled=false ExitCode=2`; and not the hostname/report-path bugs,
which were fixed). Baseline DAST and full SAST below complete normally.

- Total alerts (authenticated): 0 written (scan aborted before report)

| Severity | Count |
|----------|------:|
| High | n/a (scan aborted) |
| Medium | n/a |
| Low | n/a |
| Informational | n/a |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): **N/A** — the authenticated active scan could not
  complete in this environment, so no honest ratio can be computed from a real run.
- Honest assessment: the lecture's claim is *directionally* visible even in the partial
  data. The authenticated spider reached 88–93 in-scope URLs **as user admin**, versus the
  baseline spider which only touched the unauthenticated surface (16 URLs with findings) —
  so the authenticated attack surface was demonstrably larger. What failed was the
  active-scan phase that converts that surface into alerts, not authentication itself.
  Rather than fabricate auth numbers, this submission reports the real outcome.
- Endpoints that would have been auth-only (reachable only with the admin JWT, never
  enqueued by the anonymous baseline spider): `/rest/basket/{id}`, `/api/Cards`,
  `/api/Addresss`, `/rest/user/whoami`. They return data only when the `Authorization:
  Bearer` header is present — exactly why an authenticated scan reaches them and an
  anonymous one cannot.

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

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | DAST evidence | URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|---------------|-----|--------------|-------------------|------------|
| 1 | A03 Injection | SQLi (manually verified payload — see B.3; ZAP active scan env-blocked) | `POST /rest/user/login` | `express-sequelize-injection` + `tainted-sql-string` | `routes/login.ts:34` | High (SAST + manual payload) |
| 2 | A03 Injection | SQLi (manually verified payload; ZAP active scan env-blocked) | `GET /rest/products/search?q=` | `express-sequelize-injection` + `tainted-sql-string` | `routes/search.ts:23` | High (SAST + manual payload) |

> Route bindings confirming the SAST↔endpoint mapping (from `server.ts`):
> `app.post('/rest/user/login', login())` and
> `app.get('/rest/products/search', utils.asyncHandler(searchProducts()))`.
> **Honesty note:** the ZAP *active* scan could not run to completion on arm64 (see Task 1),
> so the DAST column is backed by a **manually issued payload against the live container**
> rather than an auto-generated ZAP alert. The SAST finding + a working live exploit is
> still a genuine two-angle correlation; only the *automated* DAST tooling was blocked.

### Strongest correlation deep-dive — login SQL injection (full auth bypass)

**1. Vulnerable code** (`routes/login.ts:34`):
```ts
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```
`req.body.email` is interpolated straight into the SQL string — no parameterization, no escaping.

**2. Working payload** (the canonical Juice Shop admin-login bypass, verified live against
the running container with `curl`):
```bash
curl -s -X POST http://127.0.0.1:3000/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"'"'"' OR true--","password":"x"}'
# -> 200 OK with {"authentication":{"token":"<JWT>", "umail":"admin@juice-sh.op", ...}}
```
The `' OR true--` closes the `email` literal, makes the `WHERE` always true, and comments
out the password check — the first row (admin) is returned and the server responds 200 with
a valid admin JWT instead of 401. (`admin@juice-sh.op'--` targets the admin specifically.)
This was confirmed by hand because the automated ZAP active scan was env-blocked (Task 1).

**Live evidence** — the `curl` above returned `200 OK` with an admin JWT:
```
{"authentication":{"token":"eyJ0eXAiOiJKV1Qi...QoRU8b2uRVnd...KTxLs",
                   "bid":1,"umail":"admin@juice-sh.op"}}
```
Decoding the JWT payload confirms full admin takeover via the injection:
`{"id":1, "email":"admin@juice-sh.op", "role":"admin", ...}`. No valid password was
supplied (`"password":"x"`) — the `' OR true--` made the `WHERE` clause unconditionally
true and commented out the password check, so the DB returned the first user (admin) and
the server issued a privileged token. (Token truncated; the full admin JWT is intentionally
not committed.)

**3. The fix** — parameterize, don't concatenate:
```ts
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  {
    replacements: { email: req.body.email || '', password: security.hash(req.body.password || '') },
    model: UserModel,
    plain: true
  }
)
```
Better still, drop the raw query entirely and use the ORM:
`UserModel.findOne({ where: { email: req.body.email, password: security.hash(req.body.password) } })`,
which binds parameters by construction.

**4. Why both angles catch it** — Static (Semgrep) follows the *taint*: `req.body.email`
(a source) reaches `sequelize.query()` (a sink) through string interpolation, with no
sanitizer in between — visible purely from the code. Dynamic testing never sees the code;
it observes *behavior*: the crafted payload above returns a 200 + admin JWT instead of a
401, proving the injection is live and reachable. Same bug, two independent angles — that's
why a finding confirmed from both static and dynamic sides is the highest-confidence type.
(Here the dynamic side is the manual `curl` proof, since ZAP's active scanner was
env-blocked; the principle is identical.)

### Reflection

In a real PR review I'd want the **DAST evidence first**. The SAST finding tells me a line
*looks* injectable, but Juice Shop is full of lookalike code (the 8 `codefixes/` false
positives prove it), so static alone invites "is this actually reachable?" debate. A ZAP
request/response showing a crafted payload returning an admin JWT is incontrovertible — it
proves exploitability, sets severity, and ends the argument. The Semgrep finding then earns
its keep by pointing the reviewer at the *exact file:line* to fix, which the DAST evidence
alone can't do. DAST proves it's real; SAST shows where to patch.

---

### PR checklist

- [x] Task 1 — ZAP baseline complete; authenticated active scan documented as arm64
  environment limitation (with log evidence + honest ratio assessment)
- [x] Task 2 — Semgrep top-10 + triage shortcut + FP
- [x] Bonus — Correlation table with 2 confirmed cross-tool findings
