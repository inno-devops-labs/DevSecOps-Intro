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

1. **unencrypted-communication** — Unencrypted communication named `Direct to App (no proxy)` between `User Browser` and `Juice Shop Application`, transferring authentication data such as credentials, tokens, or session IDs; severity **elevated**; affecting `user-browser`.
2. **unencrypted-communication** — Unencrypted communication named `To App` between `Reverse Proxy` and `Juice Shop Application`; severity **elevated**; affecting `reverse-proxy`.
3. **cross-site-scripting** — Cross-Site Scripting risk at `Juice Shop Application`; severity **elevated**; affecting `juice-shop`.
4. **missing-authentication** — Missing authentication covering communication link `To App` from `Reverse Proxy` to `Juice Shop Application`; severity **elevated**; affecting `juice-shop`.
5. **unnecessary-technical-asset** — Unnecessary technical asset named `Persistent Storage`; severity **low**; affecting `persistent-storage`.

### STRIDE mapping

- Risk 1: **I / S** — The direct browser-to-app link transfers authentication data without encryption, so an attacker on the path could read tokens or session IDs and potentially impersonate a user.
- Risk 2: **I / T** — The reverse-proxy-to-app link is unencrypted, so traffic inside the host/container boundary could be observed or modified if an attacker gains network-level access.
- Risk 3: **T / E** — Cross-site scripting allows attacker-controlled script execution in a victim’s browser, which can tamper with page behavior and may lead to privilege misuse or session abuse.
- Risk 4: **S / E** — Missing authentication on the proxy-to-app communication path weakens identity enforcement and can allow requests to reach application functionality without strong proof of identity.
- Risk 5: **I / D** — Persistent storage increases the amount of data at rest and creates an additional asset that may leak data or become unavailable if not properly protected.

### Trust boundary observation

Looking at `data-flow-diagram.png`, one trust-boundary-crossing arrow that appears in the top risks is **`Direct to App (no proxy)` from `User Browser` to `Juice Shop Application`**. This arrow crosses from the untrusted Internet/user side toward the containerized application and carries `Tokens & Sessions`, which makes it attractive to an attacker because intercepted or manipulated authentication data could enable session hijacking or request tampering.

## Task 2: Secure Variant & Diff

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 2 | -2 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 20 | -3 |

### Which rules are GONE in the secure variant?

1. `unencrypted-communication` — The public/direct `User Browser` → `Juice Shop Application` path no longer appears as an unencrypted communication finding because the secure model changes this link from `http` to `https`.
2. `unencrypted-communication` — The internal `Reverse Proxy` → `Juice Shop Application` path is also no longer reported as unencrypted because the secure model changes the backend link to `https`.
3. `unencrypted-asset` — The storage-related at-rest protection finding was reduced by changing `Persistent Storage` from `encryption: none` to `encryption: data-with-symmetric-shared-key`.
Note: the unique disappeared category list only shows `unencrypted-communication`, because two removed findings share the same category. The overall risk count confirms that three findings were removed: total risks changed from 23 to 20.

### Which rules are STILL THERE in the secure variant?

1. `cross-site-scripting` — This remains because the secure variant changes the architecture and transport/storage protections, but it does not modify the vulnerable application code. Preventing XSS would require application-level controls such as output encoding, input validation, safer templating, and a restrictive Content Security Policy.
2. `missing-waf` — This remains because the model still does not include a Web Application Firewall or equivalent request-filtering layer in front of the Juice Shop application.
3. `missing-vault` — This remains because encrypted storage is not the same as dedicated secret management. A proper vault or managed secret store would still be needed for JWT keys, API tokens, credentials, and other sensitive configuration.

### Honesty check

The total number of risks decreased from **23** to **20**, which is a reduction of **3 risks** or about **13.0%**.
The drop is useful, but it is far below 50%. This means the selected changes mostly fix a narrow part of the model: encrypted communication and encrypted storage. The remaining risks require different types of work, such as authentication design, secret management, WAF/proxy controls, application hardening, and fixing application-layer vulnerabilities like XSS and CSRF.

## Bonus Task: Auth Flow Threat Model

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 8 |
| Medium | 24 |
| Low | 14 |
| **Total** | 46 |

### Three auth-specific risks (NOT in the baseline model's top 5)

1. **sql-nosql-injection** — STRIDE: **T / E / I** — Mitigation: Use parameterized queries or prepared statements for all credential lookups. The Auth API should never build database queries by directly concatenating usernames, passwords, or other user-controlled input.

2. **missing-authentication-second-factor** — STRIDE: **S / E** — Mitigation: Require MFA or step-up authentication for admin users and sensitive operations. This reduces the impact of stolen passwords or stolen JWTs because a password alone is not enough to perform privileged actions.

3. **missing-vault** — STRIDE: **I / S / E** — Mitigation: Store JWT signing keys and other authentication secrets in a dedicated vault or managed secret store. Keys should not live directly in application config, source code, container images, or logs.

### Reflection

Building the focused auth model surfaced risks that the broader baseline architecture model did not highlight in its top 5, especially around credential lookup, MFA, JWT signing keys, and admin authorization. The baseline model showed large architectural issues such as unencrypted communication and XSS, while the auth-focused model made the login, token issuance, token verification, and admin-role checks explicit. This shows that feature-level threat models can reveal spoofing and elevation-of-privilege risks that are easy to miss in a higher-level architecture model.
