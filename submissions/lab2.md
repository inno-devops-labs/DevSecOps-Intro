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

### Top 5 risks (paste from `jq` output)
1. **cross-site-scripting** — <b>Cross-Site Scripting (XSS)</b> risk at <b>Juice Shop Application</b>; severity: elevated; affecting: juice-shop
2. **missing-authentication** — <b>Missing Authentication</b> covering communication link <b>To App</b> from <b>Reverse Proxy</b> to <b>Juice Shop Application</b>; severity: elevated; affecting: juice-shop
3. **unencrypted-communication** - <b>Unencrypted Communication</b> named <b>Direct to App (no proxy)</b> between <b>User Browser</b> and <b>Juice Shop Application</b> transferring authentication data (like credentials, token, session-id, etc.); severity: elevated; affecting: user-browser
4. **unencrypted-communication** - <b>Unencrypted Communication</b> named <b>To App</b> between <b>Reverse Proxy</b> and <b>Juice Shop Application</b>; severity: elevated; affecting: reverse-proxy
5. **unnecessary-data-transfer** - <b>Unnecessary Data Transfer</b> of <b>Tokens & Sessions</b> data at <b>User Browser</b> from/to <b>Juice Shop Application</b>; severity: low; affecting: user-browser

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **I** — A malicious actor can easily steal user credentials and/or personal data via an XSS attack.
- Risk 2: **S** — Any attacker who was access to the internal network can impersonate the proxy and send malicious requests directly to the app.
- Risk 3: **I** — Unencrypted data transfer via http is vulnerable to MitM attacks.
- Risk 4: **I** — Same as Risk 3 but within an internal network.
- Risk 5: **I** — Increases the attack surface for malicious actors, exposing user sessions unnecessarily.

### Trust boundary observation
Looking at `data-flow-diagram.png`, there is an arrow going from the internet into container network for direct communication between a web-browser and the app, completely bypassing the proxy and using an unencrypted communication channel (Risk 3). It is particularly attractive to an attacker because any credentials and session tokens can be easily intercepted with a MitM attack.