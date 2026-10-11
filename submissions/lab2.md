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

### Top 5 risks (from `labs/lab2/output/risks.json`)
1. **unencrypted-communication** — Unencrypted Communication on link *To App* (Reverse Proxy → Juice Shop Application); severity **elevated**; affecting **reverse-proxy**
2. **unencrypted-communication** — Unencrypted Communication on link *Direct to App (no proxy)* (User Browser → Juice Shop Application) carrying auth data; severity **elevated**; affecting **user-browser**
3. **cross-site-scripting** — Cross-Site Scripting (XSS) at Juice Shop Application; severity **elevated**; affecting **juice-shop**
4. **missing-authentication** — Missing Authentication on link *To App* (Reverse Proxy → Juice Shop Application); severity **elevated**; affecting **juice-shop**
5. **cross-site-request-forgery** — CSRF at Juice Shop Application via *To App* from Reverse Proxy; severity **medium**; affecting **juice-shop**

### STRIDE mapping (Lecture 2 slide 7)
- Risk 1: **I (Information Disclosure)** — HTTP link exposes tokens/credentials on the wire between proxy and app.
- Risk 2: **I (Information Disclosure)** — Plain HTTP from browser to app allows network eavesdropping on login traffic.
- Risk 3: **T (Tampering)** — XSS lets attackers inject script that alters what users see/do in the browser session.
- Risk 4: **S (Spoofing)** — Internal hop has no authentication, so any process on the host network could impersonate the proxy.
- Risk 5: **T (Tampering)** — CSRF can trick an authenticated browser into performing unwanted state-changing requests.

### Trust boundary observation
On `data-flow-diagram.png`, the arrow **User Browser → Juice Shop Application** (*Direct to App*, HTTP) crosses from the **Internet** trust boundary into the **Container Network**. It appears in the top-5 as `unencrypted-communication` because credentials and session tokens traverse that boundary in cleartext — ideal for a local-network attacker or malicious hotspot to capture and replay.

---

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High |  0 | 0 | 0 |
| Elevated | 4 | 4 | 0 |
| Medium | 14 | 13 | −1 |
| Low | 5 | 4 | −1 |
| **Total** | **23** | **21** | **−2** |

### Which rules are GONE in the secure variant?
1. `unencrypted-communication` — fixed by changing *Direct to App* and *To App* links to `protocol: https`
2. `unencrypted-asset` (Persistent Storage) — fixed by `encryption: data-with-symmetric-shared-key` on the database volume
3. `unnecessary-technical-asset` — reduced after removing plain log writes from the app asset (`data_assets_stored: []` on juice-shop)

### Which rules are STILL THERE in the secure variant?
1. **missing-authentication** (elevated) — HTTPS protects confidentiality on the wire but does not authenticate the reverse-proxy → app hop; mTLS or service tokens would be needed.
2. **cross-site-scripting** (elevated) — Transport encryption does not sanitize user-supplied review text; output encoding and CSP are still missing at the application layer.

### Honesty check
Total risk dropped only **9%** (23 → 21), well under 50%. The cheap wins (TLS + encrypted volume + declaring prepared statements) removed obvious misconfiguration findings, but most medium/low rules (CSRF, missing vault, missing WAF, SSRF, container hardening) remain. Full elimination would need app-level controls, secrets management, WAF, and build-pipeline modeling — significantly more work than the five YAML field edits.

---

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 8 |
| Medium | 26 |
| Low | 12 |
| **Total** | **46** |

### Three auth-specific risks (NOT in the baseline model's top 5)
1. **sql-nosql-injection** — STRIDE: **T (Tampering)** — Mitigation: enforce parameterized queries on Auth API → Credential Store and add input validation on login/register payloads.
2. **missing-authentication-second-factor** — STRIDE: **S (Spoofing)** — Mitigation: require MFA (TOTP/WebAuthn) on login before issuing JWTs, especially for admin-capable accounts.
3. **unguarded-access-from-internet** — STRIDE: **E (Elevation of Privilege)** — Mitigation: restrict admin endpoints to internal networks or enforce step-up authentication before privileged operations.

### Reflection
The baseline architecture model treats Juice Shop as one monolithic app and highlights transport and proxy issues. The auth-focused model surfaces login-specific threats — SQL injection at the credential store, missing 2FA on the login link, and admin routes reachable from the Internet — that are invisible when auth is folded into a generic web-server asset. Feature-level models catch abuse of credentials and tokens that architecture-level DFDs compress away.
