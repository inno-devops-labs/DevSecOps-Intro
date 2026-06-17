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
1. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity Elevated; affecting Juice Shop Application
2. **missing-authentication** — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity Elevated; affecting Juice Shop Application
3. **unencrypted-communication** — Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity Elevated; affecting Reverse Proxy
4. **unencrypted-communication** — Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data (like credentials, token, session-id, etc.); severity Elevated; affecting User Browser
5. **missing-waf** — Missing Web Application Firewall (WAF) risk at Juice Shop Application; severity Low; affecting Juice Shop Application

### STRIDE mapping
- Risk 1: **T** — XSS tampers with content that the browser executes, which changes the behavior of the page and can manipulate user actions.
- Risk 2: **S** — Missing authentication lets an attacker pretend to be a trusted caller on the proxy-to-app link.
- Risk 3: **I** — Cleartext proxy-to-app traffic can be intercepted and read in transit, exposing sensitive application data.
- Risk 4: **I** — Cleartext direct browser-to-app traffic can leak credentials and session material to anyone who can observe the network path.
- Risk 5: **D** — Without a WAF, the app has less protection against high-volume or automated hostile traffic, especially at the boundary.

### Trust boundary observation
One high-value boundary-crossing arrow in the top 5 is the direct browser-to-app path from the Internet trust boundary into the container network. It is attractive because authentication data crosses it in cleartext, so an attacker who can observe or influence that path can steal credentials or session material and immediately pivot into the app.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | -3 |
| Medium | 14 | 11 | -3 |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 17 | -6 |

### Which rules are gone in the secure variant?
1. `missing-authentication` — fixed by changing the proxy-to-app and browser-to-app links to HTTPS-only and adding authenticated proxy-to-app traffic.
2. `unencrypted-asset` — fixed by encrypting the persistent storage asset at rest.
3. `unencrypted-communication` — fixed by switching the inbound and outbound links to HTTPS.


### Which rules are still there in the secure variant?
1. `cross-site-scripting` — The transport and storage changes do not change the application’s browser-side input handling, so the XSS issue remains. A secure transport layer cannot fix unsafe DOM or template handling.
2. `unnecessary-data-asset` — The model still includes a log data asset, so Threagile continues to flag it as present even though the transport hardening is better. Removing that asset entirely would be a stronger reduction than merely encrypting the path.

### Honesty check
No. The total did not drop by more than 50%; it dropped from 23 to 17. That means the hardening changes helped, but they mainly removed transport and storage exposure rather than the deeper application-level issues. The cost-benefit is still positive, but eliminating the remaining risks would require more invasive app and edge changes.

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 5 |
| Medium | 21 |
| Low | 14 |
| **Total** | 40 |

### Three auth-specific risks
1. **missing-authentication** — STRIDE: S — Mitigation: Require a real server-side authentication step for login and registration endpoints, and reject any request that cannot prove user identity. Add rate limiting and logging so repeated unauthenticated probes do not become invisible.
2. **sql-nosql-injection** — STRIDE: T — Mitigation: Use parameterized queries consistently, validate all input at the API boundary, and keep the user store behind a narrowly scoped data access layer. The auth path is especially sensitive because a single injection bug can expose every account.
3. **cross-site-scripting** — STRIDE: T — Mitigation: Implement a strict Content Security Policy (CSP), ensure proper contextual output encoding on the Admin Endpoint, and store JWT access tokens in secure, HttpOnly cookies to protect them from client-side script theft.

### Reflection
Building the focused auth model surfaced identity and token-handling problems that the broader architecture model mostly buried under generic web-app noise, and the latest revision reduced the total risk count from 45 to 40. The smaller model makes it obvious where spoofing and elevation risks live: login, JWT issuance, protected requests, and admin authorization.
