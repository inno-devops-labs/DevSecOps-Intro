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

### Top 5 risks
1. **cross-site-scripting** — Cross-Site Scripting (XSS); severity elevated; affecting `juice-shop`
2. **missing-authentication** — Missing Authentication on link To App (Reverse Proxy → Juice Shop); severity elevated; affecting `juice-shop`
3. **unencrypted-communication** — Unencrypted Communication on Direct to App (User Browser → Juice Shop) transferring auth data; severity elevated; affecting `user-browser`
4. **unencrypted-communication** — Unencrypted Communication on link To App (Reverse Proxy → Juice Shop); severity elevated; affecting `reverse-proxy`
5. **missing-identity-store** — Missing Identity Store in threat model (referencing Reverse Proxy); severity medium; affecting `reverse-proxy`

### STRIDE mapping
- Risk 1 (XSS): **T (Tampering)** — An attacker injects malicious scripts that tamper with page content and steal user data from other sessions.
- Risk 2 (Missing Authentication): **S (Spoofing)** — Without authentication on the internal proxy-to-app link, any process reaching the app can impersonate a legitimate user.
- Risk 3 (Unencrypted Communication Browser→App): **I (Information Disclosure)** — Credentials and session tokens sent over plain HTTP can be intercepted by a network attacker.
- Risk 4 (Unencrypted Communication Proxy→App): **I (Information Disclosure)** — Internal traffic between the reverse proxy and the app is unencrypted, exposing tokens even inside the infrastructure boundary.
- Risk 5 (Missing Identity Store): **S (Spoofing)** — Without a declared identity store, there is no authoritative source to verify who is making requests, enabling identity spoofing.

### Trust boundary observation
In `data-flow-diagram.png`, the arrow **User Browser → Juice Shop Application** (Direct to App) crosses from the Internet trust boundary into the Container trust boundary while carrying authentication data over unencrypted HTTP. This arrow is particularly attractive to an attacker because it transmits credentials and session tokens in plaintext, making a simple network interception sufficient to fully compromise user accounts — no exploit required.


## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 2 | -2 |
| Medium | 14 | 12 | -2 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **19** | **-4** |

### Which rules are GONE in the secure variant?
1. `unencrypted-communication` — fixed by changing `protocol: http` to `protocol: https` on both the Direct to App and Proxy to App communication links
2. `unencrypted-asset` — fixed by setting `encryption: data-with-symmetric-shared-key` on juice-shop, persistent-storage, and webhook-endpoint assets

### Which rules are STILL THERE in the secure variant?
1. `cross-site-scripting` — XSS is an application-level vulnerability caused by missing input sanitization and output encoding in the code itself. Changing transport encryption and storage encryption has no effect on whether the app properly handles user-supplied HTML/JS input.
2. `missing-authentication` — The internal communication link from Reverse Proxy to Juice Shop Application still lacks explicit authentication declaration in the model. Switching to HTTPS encrypts the channel but does not add an authentication mechanism — a separate API key or mutual TLS would be needed to fully eliminate this risk.

### Honesty check
The total dropped by only 4 risks (17%), not more than 50%. This tells us that transport encryption and storage encryption — while important baseline hygiene — address only a small slice of the overall threat surface. The majority of remaining risks (XSS, CSRF, missing WAF, missing hardening, missing MFA) are application-level and architectural concerns that require significantly more engineering effort to eliminate. The cost-benefit is clear: these two changes were cheap (config-level) but the remaining risks require code changes, WAF deployment, MFA integration, and infrastructure hardening.
