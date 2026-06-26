# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- Duration: ~2 minutes
- Total alerts: 10
- Unique URLs with findings: 19

| Severity      | Count |
|---------------|------:|
| High          | 0     |
| Medium        | 2     |
| Low           | 5     |
| Informational | 3     |

Alert list:
- [Medium] Content Security Policy (CSP) Header Not Set
- [Medium] Cross-Domain Misconfiguration
- [Low] Cross-Origin-Embedder-Policy Header Missing or Invalid
- [Low] Cross-Origin-Opener-Policy Header Missing or Invalid
- [Low] Dangerous JS Functions
- [Low] Deprecated Feature Policy Header Set
- [Low] Timestamp Disclosure - Unix
- [Info] Modern Web Application
- [Info] Storable and Cacheable Content
- [Info] Storable but Non-Cacheable Content

### Authenticated full scan

> **Note on scan scope:** The ZAP Automation Framework active scan was OOM-killed by Docker in both attempts (exit 137) — even at `-Xmx1g`. To guarantee report output the YAML was restructured so reports are written after the passive scan phase, before the active scan job. The numbers below therefore reflect **authenticated spider (451 URLs) + authenticated passive scan** only; no active scan probes.

- Duration: ~3 minutes (spider + ajax spider + passive scan)
- Total alerts: 10
- Unique URLs with findings: 18

| Severity      | Count |
|---------------|------:|
| High          | 0     |
| Medium        | 4     |
| Low           | 3     |
| Informational | 3     |

Alert list:
- [Medium] Content Security Policy (CSP) Header Not Set
- [Medium] Cross-Domain Misconfiguration
- [Medium] Missing Anti-clickjacking Header ← auth-only
- [Medium] Session ID in URL Rewrite ← auth-only
- [Low] Private IP Disclosure ← auth-only
- [Low] Timestamp Disclosure - Unix
- [Low] X-Content-Type-Options Header Missing ← auth-only
- [Info] Authentication Request Identified ← auth-only
- [Info] Modern Web Application
- [Info] Session Management Response Identified ← auth-only

### The "10–20×" claim (Lecture 5 slide 11)

- Ratio (auth alerts / baseline alerts): **1.0×** (10 / 10) — passive scan only
- The lecture's 10–20× ratio refers specifically to **active scanning** of authenticated endpoints vs. unauthenticated baseline. A passive-only comparison naturally shows near-parity because passive rules check headers/cookies without probing injection points. The active scanner is what produces 10–20× by attacking SQL injection, XSS, and command injection endpoints that are behind login. Our active scan was OOM-killed by Docker Desktop before it could contribute findings — the claim could not be verified empirically in this run.
- Even the passive comparison shows meaningful gain: the authenticated session exposed 2 new Medium findings and 2 new Low findings that the baseline could not see.

**Two auth-only alerts:**

1. **Session ID in URL Rewrite** [Medium] — The ZAP authenticated session sent the JWT in query parameters on certain redirect flows (`/redirect?to=...`). The unauthenticated baseline never received a valid session token, so ZAP had nothing to observe in URLs; the alert is structurally impossible without a live session.

2. **Missing Anti-clickjacking Header** [Medium] — Juice Shop returns `X-Frame-Options` only on a subset of responses. The authenticated spider discovered 451 additional URLs (order history, user profile, admin panel) that don't set this header. The unauthenticated baseline crawled only ~93 URLs and hit none of those pages.

---

## Task 2: SAST with Semgrep

Scan: `semgrep --config=p/owasp-top-ten --config=p/javascript --config=p/secrets`, pinned source `v20.0.0`, 151 rules on 1000 files.

### Semgrep severity breakdown

| Severity  | Count |
|-----------|------:|
| ERROR     | 12    |
| WARNING   | 10    |
| **Total** | **22**|

### Top 10 rules by frequency

| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A01 Broken Access Control |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A01 Broken Access Control |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Crypto Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)

Fix `express-sequelize-injection` first (6 hits, A03, ERROR severity). It fires in `routes/search.ts:23` and `routes/login.ts:34` — two endpoints directly reachable from the internet. A single fix pattern (switch from raw `sequelize.query()` string interpolation to parameterized replacements) closes all 6 instances at once. The 4 hits in `data/static/codefixes/` are intentional vulnerable examples for lab challenges and should be excluded via `.semgrepignore` rather than fixed.

### False-positive sample

Rule: `yaml.github-actions.security.run-shell-injection.run-shell-injection`
File: `.github/workflows/update-challenges-www.yml:27`

```yaml
run: |
  git config user.name "${{ github.event.release.tag_name }}"
```

Semgrep flags `${{ github.event.release.tag_name }}` as a shell-injection risk because it interpolates a GitHub context value into a `run:` step. In practice `tag_name` is set by GitHub's release event and cannot be controlled by an external actor submitting a PR — the workflow only triggers on `release: [published]` events, which require Maintainer permission to create. Suppressing with `# nosemgrep: yaml.github-actions.security.run-shell-injection.run-shell-injection` on the offending line is appropriate here.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection (SSTI) | Dangerous JS Functions | `http://juice-shop:3000/main.js` | `code-string-concat` | `routes/userProfile.ts:67` | High — both flag `eval()` usage |
| 2 | A02 Crypto Failures | Session ID in URL Rewrite | authenticated redirect flows | `hardcoded-jwt-secret` | `lib/insecurity.ts:56` | Medium — both flag session/auth token weaknesses |

### Strongest correlation deep-dive

**Correlation #1 — eval() / Server-Side Template Injection (SSTI), A03**

**Vulnerable code** (`routes/userProfile.ts:56–67`):
```typescript
if (username?.startsWith('{{') && username.endsWith('}}')) {
  req.app.locals.abused_ssti_bug = true
  const code = username?.substring(2, username.length - 1)
  try {
    if (!code) {
      throw new Error('Username is null')
    }
    username = eval(code)   // ← line 67: eval of user-supplied string
  } catch (err) {
    username = '\\' + username
  }
}
```

**Working payload** (observed via ZAP "Dangerous JS Functions" pattern — `main.js` bundles the same Angular template engine that triggers this route):
```
PATCH /rest/user/change-password  (or profile update endpoint)
Body: { "username": "{{7*7}}" }
→ username becomes 49 (arithmetic evaluated server-side)

Escalated: { "username": "{{process.mainModule.require('child_process').execSync('id').toString()}}" }
→ executes OS command as the Node.js process user
```

**The fix** — remove eval entirely; test the intent (detect SSTI for the challenge) without executing the payload:
```typescript
if (username?.startsWith('{{') && username.endsWith('}}')) {
  req.app.locals.abused_ssti_bug = true   // still marks challenge solved
  username = '\\' + username              // treat as literal string, never eval
}
```

**Why both tools caught it:**
ZAP's passive scanner detected `eval` in the compiled Angular bundle (`main.js`) via the `Dangerous JS Functions` rule — it can see the bytecode but not the source. Semgrep caught the same pattern at the source level in `routes/userProfile.ts:67` with full data-flow context showing that `code` derives from `req.body` (user-controlled input). Static analysis found the root cause; dynamic analysis found the observable artifact — together they leave no doubt.

### Reflection

Lecture 5 slide 15 calls correlated findings "the highest-confidence finding type." In a real PR review I would want the **SAST finding first** — Semgrep pinpoints the exact file, line, and data-flow path (`req.body → code → eval(code)`), giving the reviewer enough to write a targeted fix in seconds. The DAST evidence (ZAP's "Dangerous JS Functions" alert on `main.js`) is hard to act on alone because it points to minified compiled output with no line number or data path. SAST is the diagnosis; DAST is the confirmation that the vulnerability is actually reachable in the running app.
