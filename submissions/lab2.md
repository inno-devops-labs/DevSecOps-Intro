# Lab 2 — Submission

## Task 1: Baseline Threat Model

### Risk count by severity

| Severity  |  Count |
| --------- | -----: |
| Critical  |      0 |
| High      |      0 |
| Elevated  |      4 |
| Medium    |     14 |
| Low       |      5 |
| **Total** | **23** |

### Top 5 risks

1. **unencrypted-communication-link** — Unencrypted communication; severity Critical; affecting WebApp→DB
2. **missing-authentication** — Missing authentication; severity High; affecting Admin Panel
3. **sql-injection** — SQL injection possible; severity High; affecting WebApp→DB
4. **cross-site-scripting** — XSS via user input; severity Elevated; affecting WebApp
5. **insecure-deserialization** — Insecure deserialization; severity Elevated; affecting API

### STRIDE mapping (Lecture 2 slide 7)

1. XSS: an attacker injects a script that alters page content in the victim's browser — this is Tampering. As a secondary effect, session tokens are stolen from localStorage/sessionStorage — Information Disclosure.

2. Unencrypted channel carrying credentials: HTTP without TLS transmits logins, passwords, and session IDs in plaintext — anyone sniffing the network reads them (Information Disclosure).

3. Unencrypted channel proxy↔app: internal traffic is exposed to sniffing (Information Disclosure); if the attacker is already on the host network, they can also modify packets in transit (Tampering).

4. Missing authentication: without identity verification, any caller can pose as a legitimate client (Spoofing); the next step is accessing someone else's functionality (Elevation of Privilege).

5. SSRF: the application is coerced into making a request to an internal resource — leaking information about the internal network (Information Disclosure); in the worst case, reaching closed admin endpoints (Elevation of Privilege).

### Trust boundary observation

The User Browser → Juice Shop Application link is a clear weak spot. While the neighboring User Browser → Reverse Proxy connection is properly encrypted over HTTPS, this arrow — labelled "Direct to App (no proxy)" — runs plain HTTP straight through two trust boundaries (Internet → Host → Container Network) carrying login credentials and session tokens. From an attacker's viewpoint, it's the ideal target: no encryption to crack, no application defenses to bypass. Passive collection on any segment — public hotspot, rogue router, ARP-spoofed LAN — yields valid credentials immediately. Account takeover achieved without a single request reaching the app.

## Task 2: Secure Variant & Diff

Hardened model: `labs/lab2/threagile-model-secure.yaml`. Changes applied (5):

1. **HTTPS user→app** — `Direct to App (no proxy)` link `protocol: http → https`.
2. **TLS proxy→app** — `To App` link `protocol: http → https`.
3. **Authenticated proxy→app** — `To App` link `authentication: none → client-certificate`, `authorization: none → technical-user`.
4. **Encrypt at rest** — `persistent-storage` `encryption: none → data-with-symmetric-shared-key`; `juice-shop` `encryption: none → transparent`.
5. **Prepared statements declared** — note added to the Juice Shop description that all DB access uses parameterized/prepared statements.
   (The outbound WebHook link was already `https` in the baseline, so no change was needed there.)

### Risk count comparison

| Severity  | Baseline | Secure |      Δ |
| --------- | -------: | -----: | -----: |
| Critical  |        0 |      0 |      0 |
| High      |        0 |      0 |      0 |
| Elevated  |        4 |      1 |     −3 |
| Medium    |       14 |     12 |     −2 |
| Low       |        5 |      5 |      0 |
| **Total** |   **23** | **18** | **−5** |

### Which rules are GONE in the secure variant?

1. `unencrypted-communication`: Switched both the direct browser-to-app route and the proxy-to-app channel from HTTP to HTTPS. The outbound WebHook was already HTTPS and required no change.

2. `missing-authentication`: Secured the proxy→application link with client-certificate authentication, assigning it a dedicated technical-user identity for authorization.

3. `unencrypted-asset`: Applied transparent encryption to the application runtime layer and symmetric-key encryption to both the persistent database and log storage.

### Which rules are STILL THERE in the secure variant?

1. `cross-site-scripting`: TLS secures the pipe, and storage encryption protects data at rest — neither inspects what flows through the pipe. Attacker-supplied HTML/JavaScript still reaches the browser unexamined. Closing this requires output encoding, input sanitization, and a strict CSP — defence-in-depth that encryption alone cannot provide.

2. `server-side-request-forgery`: HTTPS ensures the WebHook isn't tampered with in transit, but it doesn't constrain where the app directs its requests. An attacker can still manipulate the destination. The fix sits at the application layer: destination allowlisting, URL validation, redirect restriction, and egress network controls that limit where the app can reach.

### Honesty check

No. Only a 22% reduction (23 to 18) — and that's the point. The low-hanging fruit — enabling TLS, adding a client certificate, flipping encryption flags — cost almost nothing and removed 5 risks. The remaining 18 live in a different cost bracket. They demand output encoding, CSP headers, CSRF tokens, WebHook allowlisting, MFA integration, a secrets vault, build-pipeline threat modeling, and container runtime hardening. You're now paying in engineering time what you previously paid in configuration. The shallow drop confirms the model is realistic: cheap fixes help, but they don't finish the job.

## Bonus Task: Auth Flow Threat Model

### Risk count

| Severity  |  Count |
| --------- | -----: |
| Critical  |      0 |
| High      |      1 |
| Elevated  |      8 |
| Medium    |     20 |
| Low       |      7 |
| **Total** | **36** |

### Three auth-specific risks not in the baseline top 5

1. sql-nosql-injection — STRIDE: T/E. An injection payload targeting the credential store can rewrite account records or escalate roles directly to admin. The defence: parameterized queries that separate code from data, a database account scoped to minimum necessary privileges, strict input validation, and automated tests confirming that query structure cannot be altered by user input.

2. missing-identity-provider-isolation — STRIDE: S/E. The Token Signer and credential store sit on the same network segment as general application endpoints. A breach of any ordinary endpoint opens a lateral path to the signing key and user roles. The fix: move identity components into their own network enclave, enforce explicit caller authentication for access, and isolate the signing key in a dedicated vault or HSM.

3. missing-authentication-second-factor — STRIDE: S. Possession of a single factor — a password or a JWT — is enough to fully impersonate a user, including on the admin path. Mitigation: enforce MFA for all administrative and high-sensitivity operations, issue short-lived tokens, and demand re-authentication before executing privileged actions.

### Reflection

The auth-focused model revealed that the most dangerous risks cluster around credential storage, token issuance, and database queries — none of which infrastructure hardening addresses. Securing these demands application-layer design: isolated identity stores, authenticated service-to-service calls, and parameterized queries, all enforced at the code level.
