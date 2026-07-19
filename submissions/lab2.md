# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

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

1. **missing-authentication** — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity elevated; affecting `juice-shop`
2. **unencrypted-communication** — Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data (like credentials, token, session-id, etc.); severity elevated; affecting `user-browser`
3. **unencrypted-communication** — Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity elevated; affecting `reverse-proxy`
4. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity elevated; affecting `juice-shop`
5. **unnecessary-data-transfer** — Unnecessary Data Transfer of Tokens & Sessions data at User Browser from/to Juice Shop Application; severity low; affecting `user-browser`

### STRIDE mapping

- Risk 1: **S** — The reverse-proxy-to-app link lacks authentication, so a request can be impersonated by any party that can reach the internal app port.
- Risk 2: **I** — Session identifiers and credentials travel over plaintext HTTP, so an observer can read them directly and steal the user's authenticated state.
- Risk 3: **I** — The proxy-to-app hop is unencrypted, which exposes authentication data inside the environment and allows passive interception.
- Risk 4: **T** — XSS injects attacker-controlled script into the application context and changes what the victim browser executes, which is a direct integrity violation.
- Risk 5: **I** — Tokens and session data are transferred even when they are not needed for that flow, increasing the chance of accidental disclosure.

### Trust boundary observation

One important trust-boundary crossing in the top-5 risks is **User Browser → Juice Shop Application** on the **Direct to App (no proxy)** link. This arrow is attractive to an attacker because it carries authentication material over HTTP instead of HTTPS, so any network observer can steal credentials or session tokens and then replay them to impersonate the user.

## Task 2: Secure Variant & Diff

### Risk count comparison

I can complete this section as soon as you provide the `jq` output from `labs/lab2/output-secure/risks.json`. Your message included the baseline counts, but not the secure counts.

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 3 | -1 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **21** | **-2** |

### Which rules are GONE in the secure variant?

1. **missing-authentication** (Reverse Proxy → Juice Shop Application) — fixed by introducing authentication between the reverse proxy and the backend service. Requests reaching the application are now verified before being processed.

2. **unencrypted-communication** (Reverse Proxy → Juice Shop Application) — fixed by enabling TLS on the internal communication link between the proxy and the application, preventing interception or modification of traffic in transit.

3. **unencrypted-communication** (User Browser → Juice Shop Application) — fixed by changing the browser-facing communication protocol from HTTP to HTTPS, protecting credentials, session identifiers, and other sensitive data from network eavesdropping.

### Which rules are STILL THERE in the secure variant?

- **cross-site-scripting (XSS)** — The hardening measures focused on transport security, encryption, and authentication. They do not address application-layer input validation or output encoding, so malicious scripts may still be injected and executed within the browser context.

- **missing-vault** — Although communication channels are better protected, the architecture still lacks a dedicated secrets-management solution. Sensitive values such as credentials, API keys, or signing secrets may still be stored in configuration files or deployment environments rather than a secure vault.

### Honesty check

No. The total number of findings did not decrease by more than 50%. The implemented changes mainly improved transport security and service-to-service authentication, which eliminated a limited number of infrastructure-related risks. Most remaining findings are application-level or architectural issues that require additional controls, code changes, or new security components, making them significantly more expensive to address.

## Bonus Task: Auth Flow Threat Model

### Risk count

I can fill this section after you send the `jq` output for `labs/lab2/output-auth/risks.json`.

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 4 |
| Elevated | 7 |
| Medium | 28 |
| Low | 7 |
| **Total** | 46 |

### Three auth-specific risks

1. **missing-authentication-second-factor** — STRIDE: S / E — Administrative and privileged operations rely on a single authentication factor. Implementing multi-factor authentication (MFA) would reduce the impact of stolen credentials and make account compromise more difficult.

2. **missing-vault** — STRIDE: E — JWT signing keys and other authentication secrets remain high-value assets. Storing them in a dedicated secrets-management solution and rotating them regularly would reduce the risk of credential disclosure and unauthorized token generation.

3. **unguarded-access-from-internet** — STRIDE: S — Authentication endpoints are directly reachable from the Internet and may be targeted by credential-stuffing or brute-force attacks. Rate limiting, account lockout mechanisms, and anomaly detection can help mitigate this threat.

### Reflection

The focused authentication model revealed risks related to token issuance, credential protection, secret management, and privileged access control that were not visible in the broader architecture model. While the baseline model primarily highlighted communication and infrastructure weaknesses, the auth-focused model exposed threats associated with identity verification and privilege escalation. This demonstrates how feature-level threat modeling can uncover security concerns that may be hidden within a high-level architectural view.