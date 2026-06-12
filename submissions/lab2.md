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

### Top 5 risks (paste from `jq` output)

1. **missing-authentication** — <b>Missing Authentication</b> covering communication link <b>To App</b> from <b>Reverse Proxy</b> to <b>Juice Shop Application</b>; severity Elevated; affecting juice-shop
2. **unencrypted-communication** — <b>Unencrypted Communication</b> named <b>Direct to App (no proxy)</b> between <b>User Browser</b> and <b>Juice Shop Application</b> transferring authentication data (like credentials, token, session-id, etc.); severity Elevated; affecting user-browser
3. **unencrypted-communication** — <b>Unencrypted Communication</b> named <b>To App</b> between <b>Reverse Proxy</b> and <b>Juice Shop Application</b>; severity Elevated; affecting reverse-proxy
4. **cross-site-scripting** — <b>Cross-Site Scripting (XSS)</b> risk at <b>Juice Shop Application</b>; severity Elevated; affecting juice-shop
5. **unnecessary-technical-asset** — <b>Unnecessary Technical Asset</b> named <b>Persistent Storage</b>; severity Low; affecting persistent-storage

### STRIDE mapping (Lecture 2 slide 7)

For each top-5 risk, name the STRIDE letter(s) it primarily violates:

- Risk 1: **S (Spoofing)** — Without authentication on the proxy-to-app link, an attacker on the internal container network can send requests that the Juice Shop application treats as originating from the legitimate reverse proxy, completely bypassing any upstream access controls.
- Risk 2: **I (Information Disclosure)** — Authentication data (credentials, tokens, session IDs) transmitted over plain HTTP is visible to any network intermediary between the browser and the application, enabling credential theft through passive sniffing or active man-in-the-middle attacks.
- Risk 3: **I (Information Disclosure)** — Internal traffic between the reverse proxy and the Juice Shop application is unencrypted, exposing all request and response payloads — including authenticated user data — to any actor with access to the container network segment.
- Risk 4: **T (Tampering)** — XSS allows an attacker to inject malicious client-side scripts that modify page content, alter form submissions, rewrite DOM elements, and exfiltrate data that other users see and interact with in their browsers.
- Risk 5: **E (Elevation of Privilege)** — An unnecessary asset present in the architecture expands the attack surface. If Persistent Storage is present but unmanaged, it may contain default configurations or unpatched vulnerabilities that provide a foothold for attackers seeking elevated access to the broader system.

### Trust boundary observation

Looking at `data-flow-diagram.png`, the arrow **"Direct to App (no proxy)"** crosses the trust boundary from **Internet** (User Browser) into **Container Network** (Juice Shop Application).

This arrow is particularly attractive to an attacker because it carries authentication data — credentials, tokens, session IDs — over an **unencrypted HTTP connection**. An attacker positioned anywhere on the network path (rogue Wi-Fi access point, compromised router, ARP spoofing on the local network segment) can passively capture these credentials or actively inject malicious responses. The browser has no cryptographic mechanism to verify it is talking to the real Juice Shop application, making credential theft and session hijacking trivial. This single arrow violates both confidentiality and integrity of the authentication flow.

---

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

List 3 rule IDs that fired in baseline but not in secure-variant:

1. **unencrypted-communication** (Direct to App, no proxy) — fixed by changing `protocol: http` to `protocol: https` on the `user-browser → juice-shop` communication link. This eliminated the Elevated-severity risk of authentication data traversing the network in cleartext.

2. **unencrypted-communication** (Reverse Proxy → To App) — fixed by changing `protocol: http` to `protocol: https` on the `reverse-proxy → juice-shop` communication link. This eliminated the Elevated-severity risk of internal traffic between the proxy and application being exposed on the container network.

3. **unencrypted-asset** (Juice Shop Application) — fixed by changing `encryption: none` to `encryption: transparent` on the `juice-shop` technical asset. This signaled to Threagile that the application is capable of handling encrypted traffic, removing the Medium-severity flag.

4. **unencrypted-asset** (Persistent Storage) — fixed by changing `encryption: none` to `encryption: data-with-symmetric-shared-key` on the `persistent-storage` technical asset. This declared encryption at rest for the database and file storage, removing the Medium-severity flag.

### Which rules are STILL THERE in the secure variant?

Threat modeling never reaches zero risk. List 2 rules that still fire and explain why your changes didn't eliminate them:

1. **cross-site-scripting** (Elevated, juice-shop) — XSS is an application-layer vulnerability that operates entirely within the browser's same-origin policy. Adding HTTPS encrypts the transport channel but does not prevent the Juice Shop application from reflecting unsanitized user input into HTML responses. An attacker can still inject `<script>` tags via product reviews or user profiles, and those scripts will execute in victims' browsers regardless of whether the page was delivered over HTTP or HTTPS. Mitigating XSS requires server-side input validation, output encoding, and Content Security Policy headers — all code-level changes beyond the infrastructure hardening applied here.

2. **missing-authentication** (Elevated, reverse-proxy → juice-shop) — We encrypted this communication link with HTTPS, but encryption provides **confidentiality** (protecting data from being read in transit), not **authentication** (verifying the identity of the caller). The `authentication` field on this link is still set to `none`, meaning the Juice Shop application accepts requests from the reverse proxy without challenging its identity through mutual TLS, API keys, or a shared secret. An attacker who compromises the internal container network can still send requests directly to the application over HTTPS without being authenticated. Fixing this requires declaring an authentication mechanism (e.g., `mutual-tls` or `token`) on the link.

### Honesty check

Did the total drop more than 50%? **No.** The total dropped from 23 to 19, a reduction of approximately 17%.

This modest reduction reflects the nature of the hardening changes applied: we focused exclusively on **transport-layer and storage-layer fundamentals** (HTTPS on all links, encryption at rest for the database). These changes eliminated 4 risks — the entire `unencrypted-*` family — which is excellent return on investment for minimal configuration changes.

However, the majority of risks (XSS, CSRF, SSRF, missing 2FA, missing hardening, container backdooring, missing vault, missing WAF, missing build infrastructure, missing identity store) are **application-layer and architectural concerns** that cannot be addressed by flipping a protocol field or enabling storage encryption. They require:
- **Code changes:** Input validation, anti-CSRF tokens, output encoding, Content Security Policy
- **Architectural changes:** Deploying a secrets vault, configuring a WAF, implementing 2FA flows
- **Process changes:** Establishing a trusted build pipeline, container image signing, OS hardening policies

The cost-benefit analysis is instructive: for roughly 5 minutes of YAML edits, we eliminated the highest-severity risks related to data exposure in transit and at rest. Eliminating the remaining 19 risks would require days or weeks of engineering work across multiple teams. This is the core insight of threat modeling: **fix what's cheap and high-impact first, then prioritize the remainder by actual business risk rather than trying to reach zero.**

