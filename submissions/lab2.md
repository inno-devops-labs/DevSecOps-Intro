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

1. **unencrypted-communication** — Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data; severity elevated; affecting user-browser.
2. **unencrypted-communication** — Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity elevated; affecting reverse-proxy.
3. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity elevated; affecting juice-shop.
4. **missing-authentication** — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity elevated; affecting juice-shop.
5. **unnecessary-data-transfer** — Unnecessary Data Transfer of Tokens & Sessions data at User Browser from/to Juice Shop Application; severity low; affecting user-browser.

### STRIDE mapping

- Risk 1: **I** — Unencrypted communication can expose credentials, tokens, and session data to an attacker who can observe the traffic.
- Risk 2: **I** — Plain HTTP traffic between the reverse proxy and application can leak sensitive requests inside the environment.
- Risk 3: **T/E** — XSS can let an attacker tamper with page content or execute actions in the victim's browser with the victim's privileges.
- Risk 4: **S/E** — Missing authentication on the proxy-to-app link can allow requests to reach the application without properly proving identity or authorization.
- Risk 5: **I** — Tokens and session data are transferred to the browser, so unnecessary exposure increases the chance of information disclosure if the client side is compromised.

### Trust boundary observation

One important trust-boundary-crossing arrow is the user-facing traffic from **User Browser** to **Juice Shop Application**, especially the link named **Direct to App (no proxy)**. This arrow is attractive to an attacker because it crosses from an untrusted external user environment into the application and carries authentication data such as credentials, tokens, or session identifiers. If this communication is not encrypted, an attacker who can observe or interfere with the traffic may capture sensitive data or hijack a session.

## Task 2: Secure Variant & Diff

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | -3 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **19** | **-4** |

### Which rules are GONE in the secure variant?

1. `unencrypted-communication@user-browser>direct-to-app-no-proxy@user-browser@juice-shop` — fixed by changing the direct browser-to-application communication link from `protocol: http` to `protocol: https`.
2. `unencrypted-communication@reverse-proxy>to-app@reverse-proxy@juice-shop` — fixed by changing the reverse-proxy-to-application communication link from plain HTTP to HTTPS.
3. `missing-authentication@reverse-proxy>to-app@reverse-proxy@juice-shop` — fixed by declaring authentication and authorization on the internal reverse-proxy-to-application link.
4. `unencrypted-asset@persistent-storage` — fixed by changing the persistent storage asset from `encryption: none` to `encryption: data-with-symmetric-shared-key`.

### Which rules are STILL THERE in the secure variant?

1. `cross-site-scripting` — This risk still fires at the Juice Shop Application because switching communication links to HTTPS does not remove client-side injection vulnerabilities. Mitigation would require proper output encoding, input validation, safe frontend rendering, and a Content Security Policy.

2. `server-side-request-forgery` — This risk still fires because the application can still make server-side outbound requests to the WebHook endpoint. HTTPS protects the transport channel, but it does not prevent the application from being abused to call attacker-controlled or internal URLs. Mitigation would require strict URL validation, an allowlist of destinations, and egress filtering.

### Honesty check

The total risk count dropped from 23 to 19, which is a decrease of 4 risks, or about 17.4%. This is less than 50%, so the secure changes were useful but not enough to eliminate most of the modelled risks. The result shows that low-cost hardening changes such as HTTPS, authentication between internal components, and encrypted storage can remove several clear risks, but other categories such as XSS, SSRF, missing WAF, missing vault, and supply-chain risks require separate application-level and infrastructure-level work.

## Bonus Task: Auth Flow Threat Model

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 6 |
| Medium | 31 |
| Low | 10 |
| **Total** | **47** |

### Three auth-specific risks (NOT in the baseline model's top 5)

1. **`sql-nosql-injection@auth-api@credential-store@auth-api>check-credentials`** — STRIDE: **T/E** — Mitigation: Use parameterized queries/prepared statements for all credential checks, avoid string-concatenated SQL/NoSQL queries, and add tests for injection payloads on login and registration fields.

2. **`missing-authentication-second-factor@browser>admin-request@browser@admin-endpoint`** — STRIDE: **S/E** — Mitigation: Require MFA for admin users and admin-only actions, especially when the request comes from an external browser. This reduces the chance that stolen credentials or a stolen JWT alone are enough to access privileged functionality.

3. **`unguarded-access-from-internet@admin-endpoint@browser@browser>admin-request`** — STRIDE: **E** — Mitigation: Do not expose admin endpoints directly to the internet without extra protection. Restrict admin routes with server-side role checks, network allowlists, strong authentication, and monitoring for suspicious admin requests.

### Reflection

The focused auth-flow model surfaced risks that were less visible in the broader architecture model, especially around login, JWT handling, admin access, and credential-store interaction. The baseline model showed general application and transport risks, while the auth-specific model made it easier to reason about spoofing and elevation-of-privilege paths such as missing MFA, weak admin endpoint protection, and injection during credential checks.
