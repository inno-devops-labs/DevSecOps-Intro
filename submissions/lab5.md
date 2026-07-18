# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

Target: `bkimminich/juice-shop:v20.0.0` on the `lab5-net` Docker network. Scanner: `ghcr.io/zaproxy/zaproxy:stable`.

> **Environment note:** ZAP's full active scan with the AjaxSpider crawl (575+ URLs) repeatedly OOM-deadlocked the Docker Desktop / WSL2 VM on this machine (CPU dropping 16 → 0). To get a completing authenticated **active** scan, the AjaxSpider job was removed and a 16 GB WSL2 swap was configured; the active scan then completed over the traditional-spider crawl (93 URLs, `threadPerHost: 2`, 10-min cap). The baseline scan is unchanged (`zap-baseline.py`).

### Baseline (unauthenticated) scan
- Tool/mode: `zap-baseline.py` (spider + passive, no active scan), 158 URLs crawled
- Duration: ~1–2 minutes
- Total alerts: **10**

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated scan
- Tool/mode: Automation Framework — spider + passive + **active scan**, authenticated as `admin@juice-sh.op`
- Duration: ~7 minutes (active scan phase 06:12)
- Total alerts: **8**

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 2 |
| Low | 1 |
| Informational | 4 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): **8 / 10 = 0.8×**
- **Did the run match the lecture's 10–20× ratio? No — and the reason is instructive.** The lecture's multiplier assumes a *full* authenticated active scan over the complete crawl. Here the authenticated scan was deliberately constrained (AjaxSpider removed, active scan capped, single-host throttling) because the full crawl crashed the VM, so it covered fewer URLs (93 vs the baseline's 158) and produced fewer *total* alerts. The raw count is therefore misleading: what matters is **severity**, not volume. The authenticated active scan surfaced a **High-severity SQL Injection** that the unauthenticated passive baseline found 0 of — i.e. the single most serious finding of the whole lab only appeared under authentication + active testing. So qualitatively the claim holds (auth reaches the dangerous stuff); quantitatively our constrained run inverts the count.

### Two alerts found ONLY by the authenticated scan
1. **SQL Injection — High.** Found only by the authenticated active scan. Baseline missed it for two reasons: it is *passive-only* (it never injects payloads), and the vulnerable endpoint sits behind login — so even an active unauthenticated scan wouldn't reach it. ZAP, logged in as admin, actively injected SQL payloads into authenticated routes and confirmed the flaw.
2. **Session Management Response Identified / Authentication Request Identified — Informational.** These only appear because the authenticated scan actually performs the login flow (`POST /rest/user/login`) and handles the returned session token. The baseline never authenticates, so it never observes the authentication request or the session-management response, and these alerts can't fire.

---

## Task 2: SAST with Semgrep

Source: `juice-shop` cloned at tag **v20.0.0** (commit `f356a09`), matching the running container. Scanner: `semgrep/semgrep` (Docker), rulesets `p/owasp-top-ten` + `p/javascript`, severities ERROR + WARNING. 1000 files scanned, 116 rules run.

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | **22** |

### Top rules by frequency
(7 distinct rules produced all 22 findings)

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 Injection (CI) |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01 Broken Access Control |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)
Fix **`express-sequelize-injection`** first — specifically the two live hits at `routes/login.ts:34` and `routes/search.ts:23`. It's the highest-frequency ERROR rule (6), maps to OWASP A03 (Injection — the top-impact category), and it is independently confirmed by the DAST run: ZAP's only High-severity alert was a SQL Injection. A static finding that a dynamic tool also confirms is the highest-confidence finding type. Rewriting those two routes to use parameterized queries / Sequelize bound `replacements` instead of string-built SQL closes the actual exploitable SQLi at the source. (The other 4 sequelize hits are non-runtime fixtures — see below.)

### False-positive sample
`data/static/codefixes/dbSchemaChallenge_1.ts:5` — flagged `express-sequelize-injection`. I'd suppress this after review: the `data/static/codefixes/` directory holds **static educational code snippets** displayed in Juice Shop's "coding challenge" UI, not wired-up Express request handlers. The string-built query pattern matches the rule, but the file is never mounted as a live route, so it's not part of the running attack surface. 4 of the 6 `express-sequelize-injection` hits are these fixtures; only `routes/login.ts` and `routes/search.ts` are real. (Suppress via a `nosemgrep` comment or a path exclusion for `data/static/codefixes/`.)
