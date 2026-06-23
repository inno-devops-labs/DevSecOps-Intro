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

1. **cross-site-scripting** — Cross-Site Scripting (XSS); severity Elevated; affecting `juice-shop`.
2. **unencrypted-communication** — Unencrypted communication on `Direct to App (no proxy)`; severity Elevated; affecting `user-browser` and `juice-shop`.
3. **unencrypted-communication** — Unencrypted communication on `To App`; severity Elevated; affecting `reverse-proxy` and `juice-shop`.
4. **missing-authentication** — Missing authentication on `To App`; severity Elevated; affecting `juice-shop`.
5. **server-side-request-forgery** — Server-Side Request Forgery (SSRF) through `To Challenge WebHook`; severity Medium; affecting `juice-shop` and `webhook-endpoint`.

### STRIDE mapping

1. **cross-site-scripting — T (Tampering):** attacker-controlled script content changes the page behavior and executes in another user's trusted browser context.
2. **unencrypted-communication (browser to app) — I (Information Disclosure):** HTTP exposes session identifiers and other authentication data to anyone able to observe the connection.
3. **unencrypted-communication (proxy to app) — T/I (Tampering and Information Disclosure):** an attacker with access to the host or container network can read or modify traffic after TLS terminates at the proxy.
4. **missing-authentication — S/E (Spoofing and Elevation of Privilege):** an unauthenticated caller can impersonate a trusted upstream component and reach application functionality without proving its identity.
5. **server-side-request-forgery — E/I (Elevation of Privilege and Information Disclosure):** SSRF lets an attacker use the application's network privileges to reach resources and retrieve information that the attacker cannot access directly.

### Trust boundary observation

The `User Browser -> Juice Shop Application` arrow named
`Direct to App (no proxy)` crosses from the untrusted Internet boundary through
the Host boundary into the Container Network. It is particularly attractive
because it bypasses the TLS-terminating reverse proxy and sends session data over
HTTP, giving an attacker an opportunity to observe or alter authentication
traffic before it reaches the application.

## Task 2: Secure Variant & Diff

### Risk count comparison

| Severity | Baseline | Secure | Delta |
|----------|---------:|-------:|------:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 2 | -2 |
| Medium | 14 | 12 | -2 |
| Low | 5 | 4 | -1 |
| **Total** | **23** | **18** | **-5** |

### Rules gone in the secure variant

1. **unencrypted-communication** — fixed by changing direct browser access and proxy-to-application traffic from HTTP to HTTPS. The outbound WebHook also remains HTTPS.
2. **missing-authentication** — fixed by authenticating the proxy-to-application link with a client certificate and authorizing it as a technical user.
3. **unencrypted-asset** — fixed by declaring transparent encryption for the application runtime and symmetric-key encryption for persistent database and log storage.

### Which rules are STILL THERE in the secure variant?

1. **cross-site-scripting** — TLS and storage encryption protect data in transit and at rest, but they do not validate or encode attacker-controlled HTML and JavaScript. This risk still requires contextual output encoding, input handling, and a restrictive Content Security Policy.
2. **server-side-request-forgery** — HTTPS protects the WebHook connection from interception but does not prevent the application from being induced to request an attacker-selected destination. This requires destination allowlisting, URL validation, redirect restrictions, and egress network controls.

The explicit database communication link also causes Threagile to report
**sql-nosql-injection**. The model declares prepared statements and parameterized
queries as the mitigation, but Threagile 0.9.1 conservatively fires this rule for
database access protocols regardless of that description.

### Honesty check

No. The total fell from 23 to 18, a reduction of about 22%, not more than 50%.
The transport encryption, authenticated internal link, and encrypted storage are
relatively low-cost changes that remove several broad exposure risks. Eliminating
the remaining risks requires more targeted controls and architecture work, such
as XSS and CSRF defenses, WebHook egress restrictions, MFA, a WAF, a secrets
vault, build-pipeline modeling, and container hardening.

## Bonus Task: Auth Flow Threat Model

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 8 |
| Medium | 20 |
| Low | 7 |
| **Total** | **36** |

### Three auth-specific risks not in the baseline top 5

1. **sql-nosql-injection** — STRIDE: **T/E (Tampering and Elevation of Privilege)** — An injection against the credential store could alter account records or roles and grant administrator access. Use parameterized queries, a least-privileged database identity, strict input validation, and tests that verify query parameters cannot change SQL structure.
2. **missing-identity-provider-isolation** — STRIDE: **S/E (Spoofing and Elevation of Privilege)** — The Token Signer and credential store share a network boundary with ordinary application endpoints, so compromise of one endpoint creates a path toward the signing key and user roles. Place identity components in a dedicated network segment, allow only explicit authenticated callers, and keep the signing key in an isolated vault or HSM.
3. **missing-authentication-second-factor** — STRIDE: **S (Spoofing)** — A stolen password or JWT is sufficient to impersonate a user, including on the admin flow. Require MFA for administrator and sensitive actions, combine it with short-lived tokens, and re-authenticate before privileged operations.

### Reflection

The architecture-level baseline showed broad web and transport risks but did not
represent the signing key, role-bearing JWT, credential lookup, or per-request
token verification. Modeling the feature separately exposed concrete account
takeover paths: credential-store injection, compromise of a non-isolated token
signer, and single-factor authentication on privileged requests.
