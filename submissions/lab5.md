# Lab 5 — Submission

> Tooling: OWASP ZAP (`ghcr.io/zaproxy/zaproxy:stable`), Semgrep (`semgrep/semgrep`), jq.
> Juice Shop v20.0.0 container on a dedicated `lab5-net` Docker network; Semgrep ran against the
> matching `v20.0.0` source clone (honest source↔binary correspondence).
>
> ⚠️ **Environment caveat (active scan):** ZAP's **active-scan** phase repeatedly OOM-crashed the
> local Docker Desktop engine (the WSL2 VM died at the instant `activeScan` started, every run).
> To produce a stable, complete authenticated report I ran the authenticated plan through
> **spider + AJAX-spider + passive-scan** (the active-scan job removed). This is called out
> explicitly below where it affects results — notably the lecture's "10–20× more" claim, which
> is fundamentally an *active*-scan phenomenon.

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~1 minute (`zap-baseline.py`)
- Alert types: **9** · total instances: **37** · unique URLs with findings: **16**

| Severity | Count (alert types) |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 2 |

### Authenticated scan (spider + AJAX-spider + passive; active phase omitted — see caveat)
- Duration: ~3 minutes · AJAX-spider crawled **562 URLs** (vs baseline's ~93 spider URLs)
- Alert types: **10** · total instances: **35** · unique URLs with findings: **17**

| Severity | Count (alert types) |
|----------|------:|
| High | 0 |
| Medium | 4 |
| Low | 3 |
| Informational | 3 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio by **alert type**: 10 / 9 ≈ **1.1×** — nowhere near 10–20×.
- **Did it match the lecture? No — and the reason is methodological, not a contradiction of the
  lecture.** The 10–20× figure comes from *active* scanning of authenticated endpoints (ZAP
  actively injecting payloads into routes only reachable once logged in). My authenticated run
  omitted the active phase because it crashed the local Docker engine, so what's compared here is
  *passive* findings on both surfaces — and passive checks (missing headers, info disclosure) are
  largely surface-independent, hence the ~1.1× type ratio. Where the authenticated advantage
  *does* show even passively: the AJAX-spider reached **562** routes vs the baseline's ~93, and
  surfaced **6 alert types the baseline never saw** (session-management and authenticated-endpoint
  findings listed below). With the active phase, those 562 authenticated routes would each be
  payload-probed — that is where the 10–20× materialises.

### Two alerts only the authenticated scan found
1. **Session ID in URL Rewrite** (Medium) — `…/socket.io/?EIO=4&transport=polling&…&sid=<id>`.
   Unreachable to the baseline because the session id only exists *after* a successful login; the
   unauthenticated scan never established a session, so the URL-embedded `sid` never appeared.
2. **Private IP Disclosure** (Low) — `http://juice-shop:3000/rest/admin/application-configuration`.
   This admin configuration endpoint was only crawled in the authenticated run; its response leaks
   an internal IP. The baseline never authenticated, so it never exercised the `/rest/admin/*`
   surface.

---

## Task 2: SAST with Semgrep

Ran `--config=p/owasp-top-ten --config=p/javascript` over the `v20.0.0` source (115 rules, 465
files, ~99.9% parsed; `frontend/` + test specs excluded to keep the run inside the engine's memory).

### Severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | **22** |

### Top rules by frequency
| Count | Rule ID | OWASP |
|------:|---------|-------|
| 6 | javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection | A03 Injection |
| 5 | yaml.github-actions.security.run-shell-injection.run-shell-injection | A03 Injection |
| 4 | javascript.express.security.audit.express-check-directory-listing | A01 Broken Access Control |
| 4 | javascript.express.security.audit.express-res-sendfile | A04 Insecure Design |
| 1 | javascript.express.security.audit.express-open-redirect | A01 Broken Access Control |
| 1 | javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret | A07 Auth Failures |
| 1 | javascript.lang.security.audit.code-string-concat | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)
Fix **`express-sequelize-injection`** first. It is both the **highest-frequency** rule (6 hits) and
the **highest-impact** (SQL injection → authentication bypass + full data exfiltration). Critically,
2 of its 6 hits are in *live routes* — `routes/login.ts:34` and `routes/search.ts:23` — not test
fixtures. Switching those two raw `models.sequelize.query(\`…${input}…\`)` calls to parameterised
queries (replacements / bind params) closes the most real risk per unit of effort.

### False-positive sample
**`express-sequelize-injection` at `data/static/codefixes/unionSqlInjectionChallenge_1.ts:6`** is a
false positive *for the deployed-app assessment*. Files under `data/static/codefixes/` are the Juice
Shop challenge system's **before/after code snippets** — they are never wired into a live Express
route; they exist to be displayed in the "coding challenge" UI. Flagging them as exploitable SQLi
inflates the count with code that never executes as a request handler. (4 of the 6
`express-sequelize-injection` hits are these fixtures; only `login.ts` + `search.ts` are real.)

---

## Bonus: SAST/DAST Correlation

> Honest scope note: a *fully* confirmed correlation (ZAP active-scan firing an SQLi alert on the
> exact endpoint Semgrep flags) needs the active phase, which crashed this machine's Docker engine.
> What follows is an **endpoint-level correlation**: Semgrep statically proves the injection sink,
> and ZAP dynamically confirms the same endpoint is live, authenticated attack surface it reached.

### Correlation table
| # | OWASP | Semgrep finding (sink) | Semgrep file:line | ZAP dynamic evidence | Confidence |
|---|-------|------------------------|-------------------|----------------------|------------|
| 1 | A03 Injection | express-sequelize-injection (login) | routes/login.ts:34 | ZAP flagged `/rest/user/login` as **Authentication Request Identified** (endpoint live + auth-bearing) | High (static sink + reached endpoint) |
| 2 | A03 Injection | express-sequelize-injection (search) | routes/search.ts:23 | ZAP AJAX-spider crawled `/rest/products/search` (reached, parameterised by `?q=`) | Medium (reached; active probe omitted) |

### Strongest correlation deep-dive — login SQL injection (#1)

**1. Vulnerable code** (`routes/login.ts:34`):
```ts
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```
`req.body.email` is concatenated straight into the SQL string — a textbook injection sink.

**2. Working payload** (classic Juice Shop admin-login bypass) — POST `/rest/user/login`:
```json
{ "email": "' OR 1=1--", "password": "anything" }
```
The `' OR 1=1--` comments out the password check and returns the first user (admin), yielding an
authenticated admin session without credentials.

**3. The fix** — never build SQL by string interpolation; use parameterised/bound queries:
```ts
models.sequelize.query(
  'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
  { replacements: { email: req.body.email || '', password: security.hash(req.body.password || '') },
    model: UserModel, plain: true }
)
```
(Better still: use the Sequelize model layer — `UserModel.findOne({ where: { email, password } })` —
which parameterises automatically.)

**4. Why both angles see it.** Semgrep sees it **statically**: tainted `req.body.email` flows into a
raw `sequelize.query` template literal — visible without running anything. ZAP sees the endpoint
**dynamically**: it logged in through `/rest/user/login` and tagged it as an authentication request,
proving the sink is a live, reachable, security-critical route (and the natural target an active
scan would inject into). Static analysis pinpoints *where and why*; dynamic analysis proves *it's
actually exposed* — the two are complementary, which is the whole point of running both.

### Reflection (Lecture 5 slide 15)
In a real PR review I'd want the **SAST finding first**: it gives the exact file, line, and root
cause, so a reviewer can verify the fix in seconds and the result is deterministic (no flaky
environment, no auth setup). The DAST evidence is the powerful *second* input — it proves the sink
is genuinely reachable and not dead code, turning a "possible" into a "confirmed, exploitable in
prod". SAST tells you *what to fix*; DAST tells you *that it matters*.
