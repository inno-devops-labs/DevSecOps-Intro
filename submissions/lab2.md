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

### Top 5 risks (from `risks.json`)

1. **missing-authentication** — Missing Authentication covering communication link `To App` from Reverse Proxy to Juice Shop Application; severity **Elevated**; affecting `juice-shop`
2. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity **Elevated**; affecting `juice-shop`
3. **unencrypted-communication** — Unencrypted Communication named `Direct to App (no proxy)` between User Browser and Juice Shop Application transferring authentication data; severity **Elevated**; affecting `user-browser`
4. **unencrypted-communication** — Unencrypted Communication named `To App` between Reverse Proxy and Juice Shop Application; severity **Elevated**; affecting `reverse-proxy`
5. **unnecessary-technical-asset** — Unnecessary Technical Asset named Persistent Storage; severity **Low**; affecting `persistent-storage`

### STRIDE mapping

- Risk 1 (`missing-authentication`): **S — Spoofing** — Without authentication on the internal proxy→app link, any process on the host network could impersonate a legitimate user or the proxy itself and send requests directly to Juice Shop.
- Risk 2 (`cross-site-scripting`): **T — Tampering** — An attacker can inject malicious scripts into stored content (e.g. product reviews), tampering with what other users' browsers execute and potentially stealing session tokens.
- Risk 3 (`unencrypted-communication` — browser→app direct): **I — Information Disclosure** — Credentials and session tokens sent over plain HTTP can be intercepted by anyone on the same network, directly disclosing authentication data.
- Risk 4 (`unencrypted-communication` — proxy→app internal): **I — Information Disclosure** — Even after TLS is terminated at the proxy, the internal hop to the app is still unencrypted, meaning traffic on the Docker bridge network is readable in plaintext.
- Risk 5 (`unnecessary-technical-asset`): **E — Elevation of Privilege** — An unnecessarily exposed storage asset increases attack surface; if a low-privilege process can reach it, it may escalate access to the database, logs, or uploaded files stored on the volume.

### Trust boundary observation

Looking at `data-flow-diagram.png`, the arrow **"Direct to App (no proxy)"** crosses from the **Internet** trust boundary (User Browser) directly into the **Container Network** trust boundary (Juice Shop Application) over plain HTTP. This arrow is particularly attractive to an attacker because it carries authentication data (session tokens, credentials) across an untrusted network with no encryption and no proxy to enforce security headers or rate limiting — a single network position between the user and the host is enough to intercept or manipulate the entire session.

---

## Task 2: Secure Variant & Diff

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 2 | -2 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **20** | **-3** |

### Which rules are GONE in the secure variant?

1. `unencrypted-communication` (Direct to App) — fixed by changing `protocol: http` to `protocol: https` on the browser→app direct link
2. `unencrypted-communication` (Proxy→App internal) — fixed by changing `protocol: http` to `protocol: https` on the reverse proxy→app communication link
3. `missing-authentication` (Proxy→App) — fixed by declaring `authentication: token` on the internal proxy→app link, signalling to Threagile that the link is authenticated

### Which rules are STILL THERE in the secure variant?

1. `cross-site-scripting` — XSS is an application-layer vulnerability that cannot be eliminated by changing transport protocols or encryption settings in the model. Threagile fires this rule whenever a web server processes user-supplied input without declared sanitization. Eliminating it would require the application itself to implement output encoding and a strong Content-Security-Policy, which are code-level changes not expressible as model field changes.

2. `unnecessary-technical-asset` (Persistent Storage) — This rule fires because the storage asset is declared but has no direct communication link from the app in the model (Juice Shop writes to it implicitly via the volume mount rather than a declared link). Threagile interprets assets with no incoming data flow as potentially unnecessary. Fixing it requires adding an explicit `communication_link` from `juice-shop` to `persistent-storage`, which is a model completeness issue rather than a security hardening change.

### Honesty check

No, the total dropped by only ~13% (3 out of 23 risks eliminated). This is a more honest result — transport-layer hardening (HTTPS, authentication declarations) is cheap but addresses only the surface. The remaining 20 risks require application-level fixes: output encoding, input validation, CSP headers, and secrets management. Those are far costlier in developer time. The lesson is that infrastructure hardening is a necessary first step but not sufficient — real risk reduction requires investment at the application layer, which is exactly where Juice Shop concentrates its weaknesses.
