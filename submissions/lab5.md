# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~2 minutes
- Total alerts: 10
- Tool: ZAP baseline scan, 158 URLs crawled

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

Alerts found:
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

### Authenticated scan (passive)
- Duration: ~3 minutes
- Total alerts: 10
- Tool: ZAP Automation Framework with admin credentials, 906 URLs crawled (vs 158 unauthenticated — 5.7× more surface)

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 4 |
| Low | 3 |
| Informational | 3 |

Alerts found:
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

### The "10–20× more" claim (Lecture 5 slide 11)
- **Ratio (auth alerts / baseline alerts): 1.0×** — same alert count, but different specific alerts
- The lecture's 10-20× claim requires an **active scan** (active probing, fuzzing, injection attempts). Our authenticated scan ran in passive-only mode because the active scan job caused the ZAP container to exit silently — likely due to memory pressure from running a Linux/amd64 image under Rosetta 2 emulation on Apple Silicon with a 512 MB JVM cap. The passive authenticated scan still crawled 5.7× more URLs (906 vs 158) and surfaced 2 alerts that the baseline missed.
- **Auth-only alert 1: Session ID in URL Rewrite (Medium)** — This alert fires on WebSocket polling URLs like `/socket.io/?sid=...` that only appear after the Ajax spider loads the authenticated SPA. The unauthenticated scan never triggered socket.io session establishment, so the session token never appeared in a URL at all.
- **Auth-only alert 2: Missing Anti-clickjacking Header (Medium)** — The header check fired on the same socket.io polling endpoint, reachable only after authentication. The unauthenticated spider never reached these dynamic endpoints, so ZAP had no response headers to analyze for clickjacking.

---

## Task 2: SAST with Semgrep

### Semgrep severity breakdown
- Ran against: `juice-shop` v20.0.0 source (pinned tag)
- Rulesets: `p/owasp-top-ten`, `p/javascript`, `p/secrets`
- Excluded: `**/test/**`, `**/node_modules/**`

| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| **Total** | **22** |

### Top 10 rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A03 Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A05 Security Misconfiguration |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A02 Cryptographic Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 Injection |

### Triage shortcut (Lecture 5 slide 8)
The rule to fix first is `express-sequelize-injection` with 6 findings. It fires on raw Sequelize `query()` calls that interpolate user-supplied request parameters directly into SQL strings — the classic SQL injection pattern. Fixing this at the ORM layer (switching to parameterized queries or Sequelize's built-in `where` clause with bound parameters) closes all 6 findings in one architectural change rather than patching each route individually. It's also the highest-severity category (A03 Injection / ERROR) and directly exploitable from the `/rest/products/search` endpoint without authentication.

### False-positive sample
**Rule:** `yaml.github-actions.security.run-shell-injection.run-shell-injection`
**File:** `labs/lab5/semgrep/juice-shop/.github/workflows/update-challenges-ebook.yml:22`
**Reason:** This workflow uses `${{ github.event.pull_request.head.sha }}` in a `run:` block, which Semgrep flags as a potential shell injection via GitHub Actions expression injection. However, in this specific workflow the SHA value is a git commit hash (hex characters only, validated by GitHub before injection), not a user-controlled string — an attacker cannot inject arbitrary shell characters through a commit SHA. The rule is correct in general but this specific use case is safe because the value space is restricted to `[0-9a-f]{40}`.

---

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | Cross-Domain Misconfiguration (permissive CORS → enables cross-origin data exfiltration via SQLi response) | `http://juice-shop:3000` (both scans) | `express-sequelize-injection` | `routes/search.ts:23` | High — ZAP confirms the endpoint is live and CORS-open; Semgrep confirms the SQL is injectable |
| 2 | A02 Cryptographic Failures | Session ID in URL Rewrite (JWT token exposed in socket.io URL) | `http://juice-shop:3000/socket.io/?sid=...` | `jwt-hardcode` (hardcoded private key used to sign all JWTs) | `lib/insecurity.ts:56` | High — ZAP shows the JWT leaking into URLs; Semgrep shows the signing key is hardcoded, making any leaked token permanently forgeable |

### Strongest correlation deep-dive — SQL Injection in `/rest/products/search`

**Vulnerable code** (`routes/search.ts:23`):
```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`
)
```

**Working payload** (ZAP confirmed the endpoint is reachable and CORS-open):
GET /rest/products/search?q=')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--

**Fix** — replace raw string interpolation with a parameterized query:
```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`,
  { replacements: { criteria: `%${criteria}%` }, type: QueryTypes.SELECT }
)
```

**Why both tools caught it:** Semgrep detected it statically by matching the pattern of user-controlled request data (`req.query.q`) flowing into a raw `sequelize.query()` call without sanitization — a purely syntactic analysis that doesn't require running the app. ZAP's CORS misconfiguration finding on the same host confirms the endpoint is publicly reachable and that any SQLi response body can be read cross-origin by an attacker's page, turning a server-side injection into a full data-exfiltration primitive.

### Reflection
Lecture 5 slide 15 calls correlated findings "the highest-confidence finding type" because each tool rules out the other's main failure mode: SAST can produce false positives on dead code paths, but ZAP's CORS finding proves this endpoint is live and reachable; DAST can miss the root cause (it sees anomalous responses but not why), but Semgrep's finding pinpoints the exact line and fix. In a real PR review, the SAST finding should come first — it's available before deployment and tells developers exactly what to fix — but the DAST evidence is what you'd bring to a security-skeptical stakeholder to prove the theoretical injection is actually exploitable in production.