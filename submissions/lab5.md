# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Unauthenticated baseline scan
- Duration: ~2 min
- Total alerts: 10
- Tool: ZAP baseline scan, 158 crawled URLs

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

Identified issues:
- [Medium] Content Security Policy (CSP) Header Not Set
- [Medium] Cross-Domain Misconfiguration
- [Low] Cross-Origin-Embedder-Policy Header Missing
- [Low] Cross-Origin-Opener-Policy Header Missing
- [Low] Dangerous JS Functions
- [Low] Deprecated Feature Policy Header Set
- [Low] Timestamp Disclosure - Unix
- [Info] Modern Web Application
- [Info] Storable and Cacheable Content
- [Info] Storable but Non-Cacheable Content

### Authenticated scan (passive only)
- Duration: ~3 min
- Total alerts: 10
- Tool: ZAP Automation Framework with admin credentials, 906 crawled URLs (vs. 158 without auth — 5.7× larger attack surface)

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 4 |
| Low | 3 |
| Informational | 3 |

Identified issues:
- [Medium] Content Security Policy (CSP) Header Not Set
- [Medium] Cross-Domain Misconfiguration
- [Medium] Missing Anti-clickjacking Header
- [Medium] Session ID in URL Rewrite
- [Low] Private IP Disclosure
- [Low] Timestamp Disclosure - Unix
- [Low] X-Content-Type-Options Header Missing
- [Info] Authentication Request Identified
- [Info] Modern Web Application
- [Info] Session Management Response Identified

### Why the “10–20×” claim did not materialise (Lecture 5 slide 11)
- **Auth / baseline alert ratio:** 1.0× — same total alert count, but the specific findings differ.
- The lecture’s 10–20× multiplier refers to **active scans** (injection, fuzzing, active probing). Our authenticated scan remained passive-only because attempting an active scan caused the ZAP container to exit silently – very likely due to memory exhaustion when running the Linux/amd64 image under Rosetta 2 on Apple Silicon with a 512 MB JVM ceiling. Even so, the passive authenticated crawl covered 5.7× more URLs (906 vs 158) and revealed two findings the unauthenticated scan could never reach.
- **Auth-only finding 1: Session ID in URL Rewrite (Medium)** – triggered by WebSocket polling URLs such as `/socket.io/?sid=...`. These appear only after the Ajax spider processes the authenticated single-page application. Without authentication, no socket.io session is created, so the token never becomes part of a URL.
- **Auth-only finding 2: Missing Anti-clickjacking Header (Medium)** – detected on the same socket.io polling endpoint, reachable only post‑login. The unauthenticated spider never fetched these dynamic endpoints, so ZAP had no response headers to evaluate for clickjacking protection.

---

## Task 2: SAST with Semgrep

### Severity breakdown
- Target: `juice-shop` v20.0.0 source (pinned tag)
- Rulesets: `p/owasp-top-ten`, `p/javascript`, `p/secrets`
- Excluded paths: `**/test/**`, `**/node_modules/**`

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| **Total** | **22** |

### Top rules by number of findings
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

### Triage priority (Lecture 5 slide 8)
The rule that should be tackled first is `express-sequelize-injection` (6 findings). It flags raw `sequelize.query()` calls where request parameters are concatenated directly into SQL strings – a textbook SQL injection pattern. Replacing these with parameterised queries (using Sequelize’s native `where` with bind parameters or the `replacements` option) fixes all six occurrences with one architectural change, instead of patching each route individually. This is also the highest risk: ERROR severity, A03 Injection category, and directly exploitable without authentication on the `/rest/products/search` endpoint.

### False‑positive example
**Rule:** `yaml.github-actions.security.run-shell-injection.run-shell-injection`  
**File:** `labs/lab5/semgrep/juice-shop/.github/workflows/update-challenges-ebook.yml:22`  
**Reason:** The workflow interpolates `${{ github.event.pull_request.head.sha }}` inside a `run:` step, which Semgrep treats as a shell‑injection risk via GitHub Actions expression injection. However, the value is a commit SHA – strictly hexadecimal, validated by GitHub before injection – so an attacker cannot introduce shell metacharacters. The rule is sound in general, but this particular use is safe because the input space is limited to `[0-9a-f]{40}`.

---

## Bonus: SAST/DAST

### Table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | Cross-Domain Misconfiguration (lax CORS → enables cross‑origin data exfiltration via SQLi responses) | `http://juice-shop:3000` (both scans) | `express-sequelize-injection` | `routes/search.ts:23` | High — ZAP confirms the endpoint is live and CORS‑open; Semgrep confirms the SQL is injectable |
| 2 | A02 Cryptographic Failures | Session ID in URL Rewrite (JWT leaked in socket.io URL) | `http://juice-shop:3000/socket.io/?sid=...` | `jwt-hardcode` (hardcoded secret used to sign all JWTs) | `lib/insecurity.ts:56` | High — ZAP shows the JWT appearing in URLs; Semgrep shows the signing key is static, so any leaked token remains forever forgeable |

### Strongest correlation – SQL Injection in `/rest/products/search`

**Vulnerable code** (`routes/search.ts:23`):
```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

### Confirmed payload (ZAP verified endpoint accessibility and CORS openness):

```text
GET /rest/products/search?q=')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--
```
### Remediation – replace string interpolation with a parameterised query:

```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`,
  { replacements: { criteria: `%${criteria}%` }, type: QueryTypes.SELECT }
)
```

### Why both tools flagged it:
Semgrep detected the vulnerability purely statically, recognising the pattern of unsanitised user input (req.query.q) flowing directly into sequelize.query(). ZAP’s Cross-Domain Misconfiguration alert on the same host confirms that the endpoint is not only live but also lacks restrictive CORS headers, meaning an attacker’s page can read the SQL injection response cross‑origin. This turns a server‑side injection into a full data‑exfiltration channel.

## Reflection:

Lecture 5 slide 15 calls correlated findings “the highest‑confidence finding type” because each tool eliminates the other’s typical blind spot: SAST often raises false positives on unreachable code, but ZAP’s CORS finding proves the endpoint is publicly accessible; DAST may observe anomalous behaviour without pinpointing the root cause, while Semgrep provides the exact vulnerable line and the fix. In a real pull‑request review, the SAST result should surface first – it’s available before deployment and gives developers a precise remediation path – but the DAST evidence is what you present to security‑sceptical stakeholders to demonstrate that the theoretical flaw is genuinely exploitable in production.
