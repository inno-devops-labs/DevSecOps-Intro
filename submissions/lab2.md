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
| **Total** | 23 |

### Top 5 risks
1. **missing-authentication** — Missing Authentication on link "To App" (Reverse Proxy → Juice Shop Application); severity elevated; affecting `juice-shop`
2. **unencrypted-communication** — Unencrypted Communication "Direct to App (no proxy)" (User Browser → Juice Shop Application), transferring authentication data; severity elevated; affecting `user-browser`
3. **unencrypted-communication** — Unencrypted Communication "To App" (Reverse Proxy → Juice Shop Application); severity elevated; affecting `reverse-proxy`
4. **cross-site-scripting** — Cross-Site Scripting (XSS) at Juice Shop Application; severity elevated; affecting `juice-shop`
5. **unnecessary-technical-asset** — Unnecessary Technical Asset "Persistent Storage"; severity low; affecting `persistent-storage`

### STRIDE mapping (Lecture 2 slide 7)
- Risk 1 (missing-authentication): **S** (Spoofing) — without authentication on the link, an attacker can impersonate the reverse proxy and send trusted requests to the app.
- Risk 2 (unencrypted-communication, browser→app): **I** (Information Disclosure) — credentials and tokens travel in cleartext and can be intercepted on the wire.
- Risk 3 (unencrypted-communication, proxy→app): **I** (Information Disclosure) — internal traffic between proxy and app is unencrypted and can be sniffed.
- Risk 4 (cross-site-scripting): **T** (Tampering) — injected scripts alter the content served to the user's browser, and can escalate to E (Elevation) by stealing an admin session.
- Risk 5 (unnecessary-technical-asset): **I** (Information Disclosure) — an unused but declared storage asset is extra attack surface that may hold forgotten, unprotected data.

### Trust boundary observation
In `data-flow-diagram.png`, the arrow "Direct to App (no proxy)" from **User Browser** to **Juice Shop Application** crosses the trust boundary between the Internet and the application's environment. Worse, it punches straight through two boundaries at once (Internet → Host → Container Network), bypassing the Reverse Proxy entirely and landing directly in the innermost zone. It is especially attractive to an attacker because it carries authentication data (credentials, tokens, session IDs) in cleartext over HTTP, so anyone able to observe the network path can capture live credentials and hijack sessions — without ever passing the protections the proxy layer is meant to provide.

## Task 2: Secure Variant & Diff

### Hardening changes applied (in `threagile-model-secure.yaml`)
1. "Direct to App (no proxy)" link: `protocol: http` → `https`
2. "To App" link (Reverse Proxy → Juice Shop): `protocol: http` → `https`
3. "To App" link: `authentication: none` → `client-certificate`, `authorization: none` → `technical-user`
4. Persistent Storage: `encryption: none` → `data-with-symmetric-shared-key`
5. Declared in the link description that the app uses parameterized queries / prepared statements

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | -3 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 19 | -4 |

### Rules GONE in the secure variant
1. `missing-authentication` — fixed by adding `authentication: client-certificate` + `authorization: technical-user` on the Reverse Proxy → Juice Shop link.
2. `unencrypted-communication` (on "Direct to App (no proxy)", User Browser → Juice Shop) — fixed by switching that link from `http` to `https`.
3. `unencrypted-communication` (on "To App", Reverse Proxy → Juice Shop) — fixed by switching that link from `http` to `https`.

(Together these removed all three eliminated elevated risks: one missing-authentication finding and two unencrypted-communication findings.)

### Rules STILL firing in the secure variant (and why)
1. `cross-site-scripting` — XSS is an application-code flaw (unescaped output), not a transport or configuration setting. No field in the architecture model can remove it; it requires code-level fixes (output encoding, CSP), which are out of scope for a Threagile model.
2. `unencrypted-asset` — Although Persistent Storage is now encrypted, the rule still fires on other in-scope assets (e.g. the Juice Shop application itself still has `encryption: none`). Encrypting one datastore does not satisfy the rule for every asset that processes confidential data.

### Honesty check
Total risk dropped from 23 to 19 — about 17%, well under 50%. This shows that cheap, declarative hardening (HTTPS, link auth, storage encryption) removes the most obvious transport- and auth-layer risks quickly, but the majority of findings are application-level or require additional infrastructure (WAF, vault, identity store, hardening, second factor). Eliminating those would take real engineering work — code changes and new components — not one-line YAML edits. The cost-benefit is front-loaded: a few small changes kill the loudest risks, but the long tail gets progressively more expensive.

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 7 |
| Medium | 20 |
| Low | 16 |
| **Total** | 44 |

### Three auth-specific risks (NOT in the baseline model's top 5)
1. **missing-identity-provider-isolation** — STRIDE: **E** (Elevation of Privilege) — The Token Signer (which holds the JWT signing key) shares a network segment with ordinary services. Mitigation: isolate the signing component in its own segment / dedicated identity provider so that compromising a neighbouring service cannot reach the key.
2. **missing-authentication-second-factor** (Admin Endpoint) — STRIDE: **E** (Elevation of Privilege) — Admin access relies on a single JWT with no second factor, so a stolen or forged token grants full admin control. Mitigation: require MFA / step-up authentication for admin operations.
3. **sql-nosql-injection** (Auth API → Credential Store, via "Verify Credentials") — STRIDE: **S** (Spoofing) — An injection on the credential-verification query can bypass the login check (e.g. `' OR 1=1`), letting an attacker authenticate as any user. Mitigation: use parameterized queries / prepared statements and validate input on the auth path.

### Reflection
Building a feature-focused model surfaced authentication threats the architecture-level baseline could not see, because the baseline treated the app as a single "Juice Shop Application" box. By breaking the auth flow into separate assets (Auth API, Token Signer, Credential Store, protected and admin endpoints) and declaring the JWT signing key as a sensitive data asset, Threagile could reason about token forgery, signer isolation, second-factor gaps, and injection on the credential path — none of which were visible when those internals were hidden inside one process. Feature-level threat models find risks that architecture-level ones structurally cannot.