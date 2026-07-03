# Lab 5 — Submission

_SAST + DAST on Juice Shop `v20.0.0`._
Tooling: OWASP ZAP (`ghcr.io/zaproxy/zaproxy:stable`) · Semgrep CE 1.159.0 · target `bkimminich/juice-shop:v20.0.0`.

> **Setup note (honest):** the provided `zap-auth.yaml` and the analysis scripts target `localhost:3000`,
> but ZAP runs as a *separate* container. To make `localhost:3000` resolve to Juice Shop (so the provided
> plumbing works unmodified), both ZAP runs joined Juice Shop's network namespace with
> `docker run --network container:juice-shop …` instead of `--network lab5-net`. The report `@name`
> is therefore `http://localhost:3000`, which is what `compare_zap.sh`/`summarize_dast.sh` filter on.

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Tool/mode: `zap-baseline.py` (spider + **passive** only — no active payloads)
- Duration: **~45 seconds**
- Total alerts: **10** (alert types) · 42 instances · 18 unique URLs with findings

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Tool/mode: ZAP Automation Framework (`zap-auth.yaml`): spider → AJAX spider → passive → **active scan**
- Crawl coverage: spider 93 URLs, **AJAX spider 567 URLs**; active scan ran 6:12
- Duration: **~8.5 minutes** (507s wall)
- Total alerts: **12** (alert types) · 43 instances · 23 unique URLs with findings

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): **1.2×** by alert *type* (12/10); **1.02×** by instance (43/42).
- **Did my run match the lecture's ratio? No — and the reason is instructive.** The lecture's 10–20× compares
  authenticated vs unauthenticated coverage of *protected functionality*. Two things suppressed that here:
  (1) **ZAP deduplicates alerts by rule type**, so even though the authenticated AJAX spider reached ~6× more
  URLs (660 crawled vs the baseline's light passive crawl), those extra pages mostly re-triggered the *same*
  header/misconfig rules rather than new ones; and (2) the provided `zap-auth.yaml` uses **cookie** session
  management, but Juice Shop issues a **JWT bearer token** — so the authenticated session likely wasn't carried
  on every active request, blunting deep authenticated coverage. The honest headline is **qualitative, not a
  multiplier**: the baseline found **0 High** findings, while the full run surfaced a **High SQL Injection** that
  a passive scan structurally cannot find.

### Two alerts only the authenticated/full scan found
1. **SQL Injection** — *High* (CWE-89). Unreachable to the baseline because `zap-baseline.py` is **passive-only**:
   it never sends attack payloads, so injection can only be *confirmed* by the active-scan phase that injected
   `q='(` into `/rest/products/search` and `'` into the login `email` field and observed the SQL error.
2. **Session ID in URL Rewrite** — *Medium*. Unreachable to the baseline because it only appears once you crawl
   the authenticated SPA/API routes (the AJAX spider's 567 URLs) where session identifiers ride in rewritten
   URLs — pages the lighter unauthenticated crawl never visited.

---

## Task 2: SAST with Semgrep

Run: `semgrep --config=p/owasp-top-ten --config=p/javascript --config=p/secrets` against the **v20.0.0** source
clone (matching the running container), 152 rules over 830 files, 49s.

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | **22** |

### Top rules by frequency (Lecture 5 slide 8)
| Rule ID (short) | Count | OWASP category |
|-----------------|------:|----------------|
| express-sequelize-injection | 6 | A03 Injection |
| run-shell-injection (GitHub Actions) | 5 | A03 Injection (CI shell) |
| express-check-directory-listing | 4 | A05 Security Misconfiguration |
| express-res-sendfile | 4 | A01 Broken Access Control (path traversal) |
| express-open-redirect | 1 | A01 Broken Access Control |
| jwt hardcoded-jwt-secret | 1 | A02 Cryptographic Failures |
| code-string-concat | 1 | A03 Injection |

### Triage shortcut — which one rule first?
**`express-sequelize-injection`** (6 findings). It's the highest-frequency rule, it's A03 (Injection — the
highest-impact class here), and crucially **two of its six hits are live, exploitable** (`routes/search.ts:23`,
`routes/login.ts:34`) — both independently confirmed by ZAP's active scan. Fixing the one underlying pattern
(stop interpolating request data into `models.sequelize.query(...)`; use parameterized/bound queries) closes the
confirmed injection *and* the same-shaped findings in one data-access-layer change.

### False-positive sample
- **File:** `data/static/codefixes/unionSqlInjectionChallenge_1.ts:6` — **rule:** `express-sequelize-injection`.
- **Why suppress:** this file is **not running application code** — `data/static/codefixes/` holds static snippet
  fixtures that Juice Shop displays inside its "coding challenge" UI (this one even contains a deliberate, broken
  `.replace(/"|'|;|and|or/i, "")` mitigation attempt). It's never mounted as an Express route, so it has no
  runtime attack surface. The 4 `codefixes/*` SQLi hits are noise relative to the 2 real route handlers; I'd
  add a `paths-ignore: data/static/codefixes/` (or a per-finding nosemgrep) so the live `routes/*` hits stand out.

---

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI / param | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|-----------------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection (High, CWE-89) | `GET /rest/products/search?q=%27%28` (param `q`) | express-sequelize-injection | `routes/search.ts:23` | High (both agree) |
| 2 | A03 Injection | SQL Injection (High, CWE-89) | `POST /rest/user/login` (param `email`) | express-sequelize-injection | `routes/login.ts:34` | High (both agree) |

Both of ZAP's two SQL-Injection instances land on exactly the two route handlers Semgrep flagged as live
sequelize injection — independent static + dynamic agreement on the same sink.

### Strongest correlation deep-dive — product search SQLi (`routes/search.ts:23`)

**1) Vulnerable code (Semgrep, `routes/search.ts:21-23`):**
```ts
export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```
`req.query.q` (untrusted) is string-interpolated straight into a raw SQL string — the only "sanitization" is a
length cap. Classic taint: **source** `req.query.q` → **sink** `sequelize.query()`.

**2) Working payload (ZAP active scan):** `GET /rest/products/search?q='(` → `HTTP/1.1 500 Internal Server Error`
(broken SQL syntax proves injection). The canonical Juice Shop exploit extends this to a UNION read of the users
table: `?q=qwert')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--`.

**3) The fix — parameterize / bind, never interpolate:**
```ts
import { QueryTypes } from 'sequelize'
models.sequelize.query(
  'SELECT * FROM Products WHERE (name LIKE :term OR description LIKE :term) AND deletedAt IS NULL ORDER BY name',
  { replacements: { term: `%${criteria}%` }, type: QueryTypes.SELECT }
)
// or better, use the ORM: ProductModel.findAll({ where: { [Op.or]: [ {name: {[Op.like]: `%${criteria}%`}}, ... ] } })
```
Bound parameters send `criteria` as data, so `'(` or a `UNION` can never change the query's structure.

**4) Why both tools caught it:** the flaw is visible from both angles because the *shape* and the *behavior* both
betray it. SAST sees untrusted input flowing into a raw-SQL template literal (a syntactic source→sink it can
match statically); DAST sees the runtime symptom — an injected quote yields a 500 / a UNION yields extra rows —
without ever reading the code. Static tells you *where* in the source; dynamic proves it's *actually reachable
and exploitable* on the deployed instance.

### Reflection
This cross-tool agreement is the highest-confidence finding type because it removes each tool's main weakness at
once: SAST's false-positive risk (is this sink really reachable?) and DAST's blind spots (which line do I fix?).
In a real PR review I'd want the **DAST evidence first** — a 500/UNION response on a live endpoint is proof of
exploitability that no one can argue is theoretical, which gets the fix prioritized — and then immediately reach
for the **SAST file:line** to actually implement the parameterized-query fix. Proof of impact drives urgency;
the static location drives the patch.
