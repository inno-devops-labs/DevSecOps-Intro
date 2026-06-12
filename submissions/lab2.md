# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

## Task 1: Baseline Threat Model

### Risk count by severity

| Severity | Count |
|----------|-------|
| elevated | 4 |
| low | 5 |
| medium | 14 |
| Total | 23 |

### Top 5 risks

1. **missing-authentication** — no authentication between Reverse Proxy and Juice Shop; severity elevated; affects juice-shop

2. **unencrypted-communication** — browser connects directly to Juice Shop over HTTP, sending credentials in plain text; severity elevated; affects user-browser

3. **unencrypted-communication** — Reverse Proxy connects to Juice Shop over HTTP; severity elevated; affects reverse-proxy

4. **cross-site-scripting** — Juice Shop has XSS vulnerabilities; severity elevated; affects juice-shop

5. **missing-waf** — no web application firewall; severity low; affects juice-shop

### STRIDE mapping

1. **missing-authentication** — STRIDE: S (Spoofing) + E (Elevation of Privilege). Without authentication between the proxy and the app, an attacker on the same network could pretend to be the proxy and send any requests to Juice Shop, or bypass the proxy entirely.

2. **unencrypted-communication (Direct to App)** — STRIDE: I (Information Disclosure) + T (Tampering). HTTP sends credentials like JWTs and session IDs in plain text. Someone on the same network can capture them or modify requests while they are in transit.

3. **unencrypted-communication (To App via Proxy)** — STRIDE: I (Information Disclosure). Even with a reverse proxy, the internal connection from proxy to app uses HTTP. If an attacker compromises the host machine, they can read this internal traffic.

4. **cross-site-scripting** — STRIDE: T (Tampering) + I (Information Disclosure). XSS lets an attacker inject malicious scripts into the page. These scripts can steal session tokens from other users or modify what they see.

5. **missing-waf** — STRIDE: D (Denial of Service). Without a WAF, automated attacks like SQL injection, XSS, or brute force can reach the app directly and potentially crash it.

### Trust boundary observation

Looking at `labs/lab2/output/data-flow-diagram.png`, the arrow "Direct to App (no proxy)" crosses from Internet (User Browser) directly into Container Network (Juice Shop Application), bypassing the Host trust boundary entirely.

This path is attractive to attackers for several reasons:
1) it uses unencrypted HTTP, so credentials travel in plain text
2) it bypasses the reverse proxy, meaning no security headers are added to responses
3) the direct connection exposes the app's internal port 3000 to the network
4) an attacker on the same network could sniff traffic or perform man-in-the-middle attacks without crossing additional boundaries.

## Task 2: Secure Variant & Diff

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|----------|--------|----|
| elevated | 4 | 2 | -2 |
| low | 5 | 5 | 0 |
| medium | 14 | 13 | -1 |
| Total | 23 | 20 | -3 |

### Risk categories comparison

| Category | Baseline | Secure | Δ |
|----------|----------|--------|----|
| unencrypted-communication | 2 | 0 | -2 |
| unencrypted-asset | 2 | 1 | -1 |
| unnecessary-technical-asset | 2 | 2 | 0 |
| unnecessary-data-transfer | 2 | 2 | 0 |
| server-side-request-forgery | 2 | 2 | 0 |
| missing-hardening | 2 | 2 | 0 |
| missing-authentication-second-factor | 2 | 2 | 0 |
| cross-site-request-forgery | 2 | 2 | 0 |
| missing-waf | 1 | 1 | 0 |
| missing-vault | 1 | 1 | 0 |
| missing-identity-store | 1 | 1 | 0 |
| missing-build-infrastructure | 1 | 1 | 0 |
| missing-authentication | 1 | 1 | 0 |
| cross-site-scripting | 1 | 1 | 0 |
| container-baseimage-backdooring | 1 | 1 | 0 |

### Which risks are gone in the secure variant?

1. **unencrypted-communication** (2 risks) — fixed by changing HTTP to HTTPS for both the browser-to-app and proxy-to-app connections

2. **unencrypted-asset** (reduced from 2 risks to 1) — fixed by enabling encryption on Persistent Storage

### Which risks are still there in the secure variant?

1. **cross-site-scripting** — still present because HTTPS and encryption do not fix XSS. XSS is a problem in the application code, not in the network layer. Fixing it would require changing how Juice Shop handles user input and output.

2. **missing-waf** — still present because we did not add a Web Application Firewall to the model. This risk requires deploying an actual WAF in front of the application.

3. **cross-site-request-forgery** (2 instances remain) — CSRF protection requires implementation-specific anti-CSRF tokens. Our infrastructure changes did not add those.

### Honesty check

Total risks dropped from 23 to 20, a reduction of 3 risks. Our changes were simple: switching two connections from HTTP to HTTPS and enabling disk encryption. These changes eliminated the unencrypted-communication category entirely and partially fixed unencrypted-asset.

What remains are application-layer risks like XSS, CSRF, and missing WAF. These cannot be fixed with configuration changes alone. They require code changes (input validation, output encoding, anti-CSRF tokens) or additional infrastructure (a WAF).

This shows a typical trade-off in security work. Simple configuration changes give quick wins at low cost. But eliminating the remaining risks would require significantly more effort, including code review, development time, and potentially new infrastructure components.


