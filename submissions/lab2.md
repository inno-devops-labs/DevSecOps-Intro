# Lab 2 submission

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

1. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity elevated; affecting juice-shop
2. **missing-authentication** — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity elevated; affecting juice-shop
3. **unencrypted-communication** — Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data; severity elevated; affecting user-browser
4. **unencrypted-communication** — Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity elevated; affecting reverse-proxy
5. **missing-authentication-second-factor** — Missing Two-Factor Authentication covering communication link Direct to App (no proxy) from User Browser to Juice Shop Application; severity medium; affecting juice-shop

### STRIDE mapping

- Risk 1 (cross-site-scripting): **E** (Elevation of Privilege) — XSS can steal user session and grant attacker the same privileges as the victim user.
- Risk 2 (missing-authentication): **S** (Spoofing) — Without authentication between Reverse Proxy and Juice Shop, an attacker could impersonate the proxy and send malicious requests.
- Risk 3 (unencrypted-communication): **I** and **T** (Information Disclosure and Tampering) — Authentication data (credentials, tokens) is transmitted in plain text, allowing interception or modification.
- Risk 4 (unencrypted-communication): **I** and **T** (Information Disclosure and Tampering) — Internal traffic between proxy and application is unencrypted, exposing data on the internal network.
- Risk 5 (missing-authentication-second-factor): **S** (Spoofing) — If a user's password is stolen, the attacker can log in without any second verification factor.

### Trust boundary observation

Looking at `data-flow-diagram.png`, the arrow **Reverse Proxy → Juice Shop Application** crosses the trust boundary between **Host** and **Container Network**. This arrow appears in the top-5 risks as `unencrypted-communication` with severity **elevated**. This arrow uses **http** (unencrypted), which is particularly attractive to an attacker because:
1. It crosses a trust boundary between two different security zones
2. The communication is not encrypted, allowing eavesdropping or tampering
3. If an attacker compromises the Host zone, they can intercept or modify traffic to the application container
---

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 3 | -1 |
| Medium | 14 | 12 | -2 |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 20 | -3 |

### Which rules are GONE in the secure variant?

1. **unencrypted-asset** (two instances) — fixed by changing `encryption: none` to `encryption: data-with-symmetric-shared-key` for Juice Shop Application and Persistent Storage (both instances eliminated)
2. **unencrypted-communication** (one instance) — fixed by changing `protocol: http` to `protocol: https` for User Browser → Juice Shop communication link; one encrypted communication link remains (Reverse Proxy → Juice Shop, which still uses http)

### Which rules are STILL THERE in the secure variant?

1. **cross-site-scripting** — This risk remains because XSS requires application-level fixes (CSP headers, input sanitization, output encoding). Adding HTTPS and disk encryption does not affect how the application handles user input.

2. **missing-authentication-second-factor** — This risk remains because 2FA is an architectural decision not related to transport encryption or disk encryption. Eliminating it would require implementing actual two-factor authentication in the application code.

3. **missing-authentication** — One instance still remains on the Reverse Proxy → Juice Shop communication link. HTTPS was added only to the User Browser → App link, but the internal proxy-to-app communication still lacks authentication.

4. **unencrypted-communication** — One instance still remains on the Reverse Proxy → Juice Shop communication link (http). Only the direct User Browser → App link was upgraded to https; the internal traffic remains unencrypted.

### Honesty check

No, the total dropped by only 13% (from 23 to 20). This shows that basic hardening changes (HTTPS, encryption at rest) are cheap to implement but only eliminate a small subset of risks — specifically those related to data exposure. The remaining risks require more expensive application-level changes (code fixes, architectural improvements, additional security controls). This is a realistic cost-benefit scenario: low-effort changes provide some security improvement, but reaching a truly secure state requires significantly more work.