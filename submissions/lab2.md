# Lab 2 — Submission

## Task 1: Baseline Threat Model

### Risk count by severity

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | **23** |

Generated with:
```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model.yaml \
  -output /app/work/output
jq '[.[] | .severity] | group_by(.) | map({severity: .[0], count: length})' \
  labs/lab2/output/risks.json
```

### Top 5 risks

1. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity **elevated**; affecting `juice-shop`
2. **unencrypted-communication** — Unencrypted Communication on link *Direct to App (no proxy)* between User Browser and Juice Shop Application, transferring authentication data; severity **elevated**; affecting `user-browser`
3. **unencrypted-communication** — Unencrypted Communication on link *To App* between Reverse Proxy and Juice Shop Application; severity **elevated**; affecting `reverse-proxy`
4. **missing-authentication** — Missing Authentication covering communication link *To App* from Reverse Proxy to Juice Shop Application; severity **elevated**; affecting `juice-shop`
5. **missing-build-infrastructure** — Missing Build Infrastructure in the threat model; severity **medium**; affecting `juice-shop`

### STRIDE mapping (Lecture 2 slide 7)

- Risk 1 (`cross-site-scripting`): **T + S** — XSS lets an attacker inject scripts that tamper with page content (Tampering) and act as the victim user, effectively spoofing their identity to the server (Spoofing).
- Risk 2 (`unencrypted-communication`, user→app): **I** — Credentials and session tokens sent over plaintext HTTP can be captured by any network observer, directly disclosing confidential data (Information Disclosure).
- Risk 3 (`unencrypted-communication`, proxy→app): **I** — Even after TLS terminates at the proxy, the internal hop to the app is unencrypted; a process on the same host can intercept tokens in transit (Information Disclosure).
- Risk 4 (`missing-authentication`, proxy→app): **S** — Any process that can reach the app's internal port can impersonate a legitimate downstream request with no credential challenge (Spoofing).
- Risk 5 (`missing-build-infrastructure`): **T** — Without a declared, verifiable build pipeline, supply-chain tampering (malicious dependency or image layer substitution) is undetectable (Tampering).

### Trust boundary observation

In `data-flow-diagram.png` the arrow **User Browser → Juice Shop Application** (*Direct to App, no proxy*) crosses from the **Internet** trust boundary directly into the **Container Network**, bypassing the reverse proxy entirely. This link is especially attractive to an attacker because it carries `tokens-sessions` data assets over plain HTTP — meaning any network observer between the client and the host machine captures live session tokens with zero effort, and the app cannot distinguish a legitimate browser from a replayed stolen session.

---

## Task 2: Secure Variant & Diff

### Changes made to `threagile-model-secure.yaml`

| Change | Location | Before → After |
|--------|----------|----------------|
| Force HTTPS on direct user link | `User Browser → Direct to App` communication link | `protocol: http` → `protocol: https` |
| TLS + auth on internal proxy link | `Reverse Proxy → To App` communication link | `protocol: http, authentication: none` → `protocol: https, authentication: token` |
| Encrypt storage at rest | `Persistent Storage` technical asset | `encryption: none` → `encryption: data-with-symmetric-shared-key` |
| Declare parameterized queries | `Juice Shop Application` description | Added note that all DB queries use prepared statements |
| Strengthen internal auth | `Reverse Proxy → To App` | `authorization: none` → `authorization: technical-user` |

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | **−3** |
| Medium | 14 | 13 | **−1** |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **19** | **−4** |

### Which rules are GONE in the secure variant?

1. `unencrypted-communication` (link *Direct to App (no proxy)*, User Browser → Juice Shop Application) — fixed by changing `protocol: http` → `protocol: https` on the direct browser-to-app link.
2. `unencrypted-communication` (link *To App*, Reverse Proxy → Juice Shop Application) — fixed by changing `protocol: http` → `protocol: https` on the internal proxy-to-app link.
3. `missing-authentication` (link *To App*, Reverse Proxy → Juice Shop Application) — fixed by adding `authentication: token` and `authorization: technical-user` on the same proxy→app link.

### Which rules are STILL THERE in the secure variant?

1. **`cross-site-scripting`** (elevated) — XSS is a code-level vulnerability in how the application renders untrusted user input. Changing transport protocol and encryption at rest does nothing to prevent a stored XSS payload from executing in another user's browser. Eliminating this requires output encoding and a Content-Security-Policy enforced at the application layer.

2. **`unencrypted-asset`** (medium) — The `Juice Shop Application` asset itself still has `encryption: none` at the process level. Threagile flags this separately from storage encryption: even though the volume is now encrypted, the running process holds plaintext data in memory and does not declare application-level encryption of data assets it processes (user accounts, tokens). Fixing this would require declaring `encryption: data-with-symmetric-shared-key` on the technical asset itself, not just the storage.

### Honesty check

The total dropped from 23 to 19 — a **17% reduction**, well under 50%. This makes sense: transport and storage hardening are infrastructure-level changes that address a handful of rules in Threagile's ruleset. The majority of remaining risks (`cross-site-scripting`, `cross-site-request-forgery`, `missing-vault`, `missing-identity-store`, `server-side-request-forgery`, `container-baseimage-backdooring`, etc.) are architectural and code-level issues that require application changes, a secrets management system, WAF deployment, and a verified build pipeline. The five one-field changes we made are cheap wins with high signal-to-noise on the most severe (elevated) findings, but they account for only a small fraction of total remediation effort.

---

## Bonus Task: Auth Flow Threat Model

### Risk count

| Severity | Count |
|----------|------:|
| High | 2 |
| Elevated | 11 |
| Medium | 22 |
| Low | 5 |
| **Total** | **40** |

Generated with:
```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-auth.yaml \
  -output /app/work/output-auth \
  -generate-risks-excel=false -generate-tags-excel=false
```

### Three auth-specific risks (NOT in the baseline model's top 5)

1. **`sql-nosql-injection`** — STRIDE: **T (Tampering)** — The Admin Endpoint issues unparameterized SQL queries against the Credential Store. An attacker with a forged admin JWT can craft malicious input in admin API calls to modify or exfiltrate any user record. Mitigation: enforce parameterized queries (prepared statements) for all database access in the admin routes.

2. **`server-side-request-forgery`** — STRIDE: **S (Spoofing)** — The Auth API makes an internal HTTP call to the Token Signer with no authentication on that link. An attacker who controls the Auth API process (or can inject into its request path) can redirect that call to an arbitrary internal target, making the Token Signer component appear to be a trusted internal service when it is not. Mitigation: restrict the Token Signer to `localhost` only and add `authentication: token` on the inter-process link.

3. **`unguarded-access-from-internet`** — STRIDE: **E (Elevation of Privilege)** — The Admin Endpoint is directly reachable from the Internet trust boundary with only a JWT role claim as the gate — no IP allowlist, no WAF, no second factor. A forged or stolen admin token grants immediate access to all user management operations. Mitigation: place admin routes behind a network-level control (IP allowlist or VPN) and enforce MFA for any account that can obtain an admin-role token.

### Reflection

The focused auth model surfaced three classes of risk that the architecture-level baseline missed entirely: SQL injection in the admin path (because the baseline model has no database communication links at all), SSRF on the internal token-signing call (because the baseline treats Juice Shop as a single monolithic asset), and unguarded direct internet access to the admin endpoint (because the baseline's trust boundaries don't distinguish between user and admin routes). Feature-level threat models force you to draw the communication links that matter for a specific flow, which reveals intra-component attack surfaces that an architecture overview deliberately abstracts away.
