# Lab 2 Submission

## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|------:|
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | **23** |

### Top 5 risks (paste from `jq` output)
1. **unencrypted-asset@juice-shop** — Unencrypted Technical Asset named Juice Shop Application; severity medium; affecting `juice-shop`.
2. **unencrypted-asset@persistent-storage** — Unencrypted Technical Asset named Persistent Storage; severity medium; affecting `persistent-storage`.
3. **missing-identity-store@reverse-proxy** — Missing Identity Store in the threat model (example asset Reverse Proxy); severity medium; affecting `reverse-proxy`.
4. **missing-authentication@reverse-proxy>to-app@reverse-proxy@juice-shop** — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity elevated; affecting `juice-shop`.
5. **cross-site-request-forgery@juice-shop@user-browser>direct-to-app-no-proxy** — Cross-Site Request Forgery risk involving the Direct-to-App (no proxy) path; severity medium; affecting `juice-shop`.

### STRIDE mapping (Lecture 2 slide 7)
- missing-authentication: **A** — attacker can bypass authentication on the app-facing reverse-proxy link.
- cross-site-request-forgery: **S** — an attacker can cause a user's browser to perform actions without their intent, effectively acting as the user.
- unencrypted communication (Direct to App): **I/D** — unprotected traffic can be intercepted (Disclosure) or modified (Tampering).
- unencrypted communication (To App): **I/D** — internal HTTP traffic exposes session/token traffic in the container network to interception or modification.
- unencrypted asset (Juice Shop Application / Persistent Storage): **D** — the asset is not encrypted and sensitive data can be disclosed if accessed.

### Trust boundary observation
The `Direct to App (no proxy)` arrow crosses the untrusted Internet trust boundary directly into `Juice Shop Application`. This path is attractive because it bypasses the reverse proxy controls and exposes authentication/session data to attackers.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 3 | -1 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **21** | **-2** |

The secure variant was implemented by hardening `Direct to App (no proxy)` and `To App` to HTTPS, enabling encryption on `Persistent Storage`, and adding a database access link with prepared-statement documentation in the description.


### Which rules are GONE in the secure variant?
1. `unencrypted-communication@user-browser>direct-to-app-no-proxy@user-browser@juice-shop` — fixed by switching direct browser-to-app traffic to `protocol: https`.
2. `unencrypted-communication@reverse-proxy>to-app@reverse-proxy@juice-shop` — fixed by changing the proxy→app link to `protocol: https` and adding link-level authentication.
3. `missing-authentication@reverse-proxy>to-app@reverse-proxy@juice-shop` — fixed by introducing authentication/authorization controls on the reverse-proxy→app communication link.

### Which rules are STILL THERE in the secure variant?
1. `cross-site-scripting@juice-shop` — The application still processes untrusted input in contexts that allow script execution; transport and storage improvements do not eliminate injection vulnerabilities. Fixing this requires code changes (input validation and output encoding) and runtime policies such as a Content Security Policy to reduce impact.

2. `missing-identity-store@reverse-proxy` — The model still lacks a centralized identity store, so identity lifecycle and authoritative authentication are not enforced by design. Introducing an identity provider and integrating it into the architecture is required to address this risk, which is a larger design change beyond simple configuration.

### Honesty check
No — the total risk count dropped only slightly (from 23 to 21, ~8.7%), which is well below a 50% reduction. This indicates that the targeted hardening steps (HTTPS, storage encryption, database access controls) produced modest improvements for transport and storage risks, but many remaining risks are application-level and require more invasive work (code fixes, identity integration, build hardening) with higher development cost. The cost-benefit therefore favors pairing infrastructure hardening with prioritized application fixes rather than attempting to eliminate all risks through infrastructure changes alone.

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 1 |
| Medium | 11 |
| Low | 6 |
| **Total** | **18** |

### Three auth-specific risks (NOT in the baseline model's top 5)
For each, name:
- The rule ID Threagile fires
- The STRIDE letter
- A 1-2 sentence mitigation in plain English

1. **sql-nosql-injection@auth-api@user-db@auth-api>auth-userdb** — STRIDE: T — Mitigation: Use parameterized queries / prepared statements and validate input strictly on the Auth API. Additionally, run the Auth API with a least-privilege DB account and restrict DB permissions to only what's necessary.

2. **missing-identity-store@token-signer** — STRIDE: S — Mitigation: Introduce a centralized identity provider or identity store to manage credentials and identity lifecycle for the authentication components. Integrate service authentication and rotate credentials centrally so tokens and keys are managed and audited.

3. **missing-authentication@auth-api>auth-tokensigner@auth-api@token-signer** — STRIDE: S — Mitigation: Require authenticated, authorized service-to-service calls (for example mTLS or signed service tokens) between the Auth API and the Token Signer, and enforce authorization checks. Also restrict network access so only the Auth API can reach the Token Signer.

### Reflection (2-3 sentences)
Building a focused auth model revealed that many high-impact risks concentrate around credential handling, token issuance, and database access. Infrastructure hardening alone is insufficient; secure authentication needs careful design (identity stores, authenticated service-to-service calls, parameterized DB access) and code-level fixes to fully mitigate these risks.



