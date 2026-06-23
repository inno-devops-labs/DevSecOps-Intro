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

1. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity: elevated; affecting: juice-shop
2. **unencrypted-communication** — Unencrypted Communication named "Direct to App (no proxy)" between User Browser and Juice Shop Application transferring authentication data; severity: elevated; affecting: user-browser
3. **unencrypted-communication** — Unencrypted Communication named "To App" between Reverse Proxy and Juice Shop Application; severity: elevated; affecting: reverse-proxy
4. **missing-authentication** — Missing Authentication covering communication link "To App" from Reverse Proxy to Juice Shop Application; severity: elevated; affecting: juice-shop
5. **server-side-request-forgery** — SSRF risk at Reverse Proxy server-side web-requesting Juice Shop Application via "To App"; severity: medium; affecting: reverse-proxy

### STRIDE mapping

- Risk 1 (cross-site-scripting): **T (Tampering)** — Attacker injects malicious scripts into page content, tampering with data seen by other users and stealing their session tokens.
- Risk 2 (unencrypted-communication, direct): **I (Information Disclosure)** — HTTP traffic between browser and app is unencrypted; credentials and session tokens transmitted in plaintext are visible to network observers.
- Risk 3 (unencrypted-communication, proxy→app): **I (Information Disclosure)** — Internal proxy-to-app leg uses HTTP; any attacker with access to the host network can intercept tokens and session data in transit.
- Risk 4 (missing-authentication): **S (Spoofing)** — The proxy-to-app link has no authentication; any process on the host network can impersonate the proxy and send unauthenticated requests directly to the app.
- Risk 5 (server-side-request-forgery): **S (Spoofing)** — The reverse proxy can be abused to make server-side requests to internal resources, allowing an attacker to spoof the proxy identity and reach internal services.

### Trust boundary observation

Looking at data-flow-diagram.png, the arrow "Direct to App (no proxy)" crosses the trust boundary from Internet (User Browser) directly into the Container Network (Juice Shop Application) over plain HTTP. This arrow is particularly attractive to an attacker because it bypasses the reverse proxy entirely — no TLS termination, no security headers, no authentication — meaning credentials and session tokens flow in plaintext across the most exposed boundary in the architecture.

---

## Task 2: Secure Variant & Diff

### Changes made to threagile-model-secure.yaml

1. All protocol: http communication links changed to protocol: https
2. Persistent Storage encryption changed from none to data-with-symmetric-shared-key
3. Proxy→App link authentication changed from none to token
4. Proxy→App link authorization changed from none to technical-user
5. Proxy→App description updated to declare use of parameterized queries (prepared statements)

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|--------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | -3 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **19** | **-4** |

### Which rules are GONE in the secure variant?

1. unencrypted-communication (Direct to App) — fixed by changing protocol: http to protocol: https on the Browser→App direct link
2. unencrypted-communication (Proxy→App) — fixed by changing protocol: http to protocol: https on the Proxy→App internal link
3. missing-authentication (Proxy→App) — fixed by adding authentication: token and authorization: technical-user on the Proxy→App link

### Which rules are STILL THERE in the secure variant?

1. cross-site-scripting at Juice Shop Application — XSS is an application-level vulnerability caused by insufficient output encoding in the app code. Switching to HTTPS and encrypting storage does not affect how the app handles user-supplied input in HTML rendering; this risk requires code-level fixes (output escaping, CSP headers) that cannot be expressed through Threagile communication link fields alone.

2. missing-build-infrastructure — This risk fires because the threat model declares no CI/CD pipeline or build system asset. Adding HTTPS and encryption to communication links does not introduce a build infrastructure component into the architecture; a separate set of changes would be needed to suppress this rule.

### Honesty check

The total dropped by 4 risks (about 17%), not more than 50%. This tells us that the five hardening changes address only the most obvious transport-layer and authentication gaps. The remaining 19 risks are architectural and application-level issues (XSS, missing vault, missing WAF, SSRF, container hardening) that require deeper engineering investment: secure coding practices, secret management infrastructure, network segmentation, and WAF deployment. The cost-benefit is strong for the changes made (low effort, high signal on elevated risks), but the bulk of the risk surface requires sustained engineering work, not just configuration tweaks.

---

## Bonus Task: Auth Flow Threat Model

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 9 |
| Medium | 18 |
| Low | 8 |
| **Total** | **36** |

### Three auth-specific risks NOT in the baseline top 5

1. **sql-nosql-injection** — STRIDE: **T (Tampering)** — The Auth API queries User DB using string-concatenated SQL with user-supplied credentials, allowing an attacker to inject OR 1=1 into the login form to bypass authentication entirely. Mitigation: replace all dynamic SQL with parameterized queries (prepared statements) in the login and registration handlers.

2. **unguarded-access-from-internet** — STRIDE: **E (Elevation of Privilege)** — The Auth API and Admin Endpoint are directly reachable from the Internet trust boundary without any WAF, rate limiter, or API gateway in front, allowing attackers to brute-force credentials or attempt JWT forgery attacks at full speed. Mitigation: place a WAF or API gateway with rate limiting and IP-based throttling in front of all auth endpoints.

3. **missing-hardening** at User DB — STRIDE: **I (Information Disclosure)** — The User DB (SQLite) runs without hardening controls: no encryption at rest, no access controls beyond the container boundary, and no audit logging of credential queries. If an attacker gains container access they can read the raw credential hashes directly from the database file. Mitigation: enable encryption at rest for the database file, restrict DB file permissions to the app process only, and log all authentication queries for anomaly detection.

### Reflection

Building the focused auth model surfaced risks that the baseline architecture model missed entirely because the baseline treated the entire Juice Shop as a single process asset without modelling the internal auth components separately. By decomposing the flow into Browser → Auth API → Token Signer → User DB → Admin Endpoint, Threagile was able to fire SQL injection, unguarded internet access, and missing hardening rules that are invisible when auth logic is hidden inside a monolithic asset. Feature-level threat models consistently find implementation-level risks that architecture-level models cannot see because they lack the resolution to distinguish one API endpoint from another.
