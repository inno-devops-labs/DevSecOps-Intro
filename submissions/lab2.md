### Task 1: Baseline Threat Model

### Risk count by severity

| Severity | Count |
| -------- | ----- |
| Critical | 0     |
| High     | 0     |
| Elevated | 4     |
| Medium   | 14    |
| Low      | 5     |
| Total    | 23    |

### Top 5 risks (paste from jq output)

1. cross-site-scripting — <b>Cross-Site Scripting (XSS)</b> risk at <b>Juice Shop Application</b>; severity elevated; affecting juice-shop

2. missing-authentication — <b>Missing Authentication</b> covering communication link <b>To App</b> from <b>Reverse Proxy</b> to <b>Juice Shop Application</b>; severity elevated; affecting juice-shop

3. unencrypted-communication — <b>Unencrypted Communication</b> named <b>Direct to App (no proxy)</b> between <b>User Browser</b> and <b>Juice Shop Application</b> transferring authentication data (like credentials, token, session-id, etc.); severity elevated; affecting user-browser

4. unencrypted-communication — <b>Unencrypted Communication</b> named <b>To App</b> between <b>Reverse Proxy</b> and <b>Juice Shop Application</b>; severity elevated; affecting reverse-proxy

5. unnecessary-technical-asset — <b>Unnecessary Technical Asset</b> named <b>Persistent Storage</b>; severity low; affecting persistent-storage

### STRIDE mapping (Lecture 2 slide 7)

For each top-5 risk, name the STRIDE letter(s) it primarily violates:

* Risk 1: T — Cross-Site Scripting allows attackers to inject and manipulate content executed in the victim's browser, which is primarily a Tampering issue.

* Risk 2: S — Missing authentication on the proxy-to-app link could allow unauthorized systems or users to impersonate trusted components, making it a Spoofing risk.

* Risk 3: I — Unencrypted communication between the browser and the app may expose credentials and session tokens to interception, which is an Information Disclosure issue.

* Risk 4: I — Unencrypted communication between the reverse proxy and the application can leak internal traffic if the network is compromised, also an Information Disclosure risk.

* Risk 5: I — An unnecessary technical asset increases the chance of exposing stored data or logs, which primarily relates to Information Disclosure.

### Trust boundary observation

One important arrow crossing a trust boundary is “Direct to App (no proxy)” between User Browser and Juice Shop Application. This flow crosses from the untrusted Internet boundary into the application environment and carries authentication data such as session IDs and credentials. It is particularly attractive to an attacker because the traffic is unencrypted HTTP, making interception or manipulation possible through man-in-the-middle attacks.


## Task 2: Secure Variant & Diff

### Risk count comparison

| Severity  | Baseline | Secure |      Δ |
| --------- | -------: | -----: | -----: |
| Critical  |        0 |      0 |      0 |
| High      |        0 |      0 |      0 |
| Elevated  |        4 |      1 |     -3 |
| Medium    |       14 |     10 |     -4 |
| Low       |        5 |      4 |     -1 |
| **Total** |   **23** | **15** | **-8** |

### Which rules are GONE in the secure variant?

List 3 rule IDs that fired in baseline but not in secure-variant:

1. `missing-authentication` — fixed by changing the **Reverse Proxy → Juice Shop** communication link from `authentication: none` to `authentication: credentials` and adding authorization controls.
2. `unencrypted-communication` — fixed by removing the **Direct to App (no proxy)** HTTP connection between the browser and Juice Shop.
3. `unencrypted-communication` — fixed by changing the **Reverse Proxy → Juice Shop** communication link from `protocol: http` to `protocol: https`.

### Which rules are STILL THERE in the secure variant?

Threat modeling never reaches zero risk. List 2 rules that still fire and explain why your changes didn't eliminate them (2-3 sentences each).

1. `cross-site-scripting`

   This risk remains because it originates from the application itself rather than the network architecture. The secure variant improved transport security and authentication, but it did not modify Juice Shop source code, input validation, output encoding, or browser-side protections needed to fully mitigate XSS.

2. `unnecessary-technical-asset`

   This rule remains because the application still uses persistent storage for databases, uploads, and logs. Although storage encryption was enabled, the asset itself is still required for application functionality and therefore continues to contribute to the overall attack surface.

### Honesty check

No. The total number of risks dropped from 23 to 15, which is a reduction of approximately 35%. This demonstrates that relatively simple architectural hardening measures such as TLS, authentication, and removal of unnecessary communication paths can eliminate several significant risks. However, the remaining risks are largely application-level issues that require more substantial engineering effort, including secure coding practices, validation controls, and architectural redesign.