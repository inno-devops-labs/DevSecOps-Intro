# Lab 2: Threat Modeling with Threagile

## Task 1: Initial Threat Model

### Risk Distribution by Severity

| Severity  |  Count |
| --------- | -----: |
| Critical  |      0 |
| High      |      0 |
| Elevated  |      4 |
| Medium    |     14 |
| Low       |      5 |
| **Total** | **23** |

### Five Most Significant Risks

1. **missing-authentication** — Lack of authentication on the `To App` communication path connecting the `Reverse Proxy` and the `Juice Shop Application`; severity: Elevated; impacts `juice-shop`.
2. **unencrypted-communication** — Unencrypted communication over `Direct to App (no proxy)` between the `User Browser` and the `Juice Shop Application`, including transmission of authentication-related information; severity: Elevated; impacts `user-browser`.
3. **unencrypted-communication** — Unencrypted communication on the `To App` link between the `Reverse Proxy` and the `Juice Shop Application`; severity: Elevated; impacts `reverse-proxy`.
4. **cross-site-scripting** — Cross-Site Scripting vulnerability affecting the `Juice Shop Application`; severity: Elevated; impacts `juice-shop`.
5. **missing-identity-store** — Absence of a modeled identity store within the architecture, associated with the `Reverse Proxy`; severity: Medium; impacts `reverse-proxy`.

### STRIDE Classification

* Risk 1: **S/E** — Missing authentication on backend communication enables attackers to imitate trusted proxy traffic and potentially access application functionality without the required trust validation.
* Risk 2: **I/S** — The use of plain HTTP may expose session tokens, allowing attackers to reuse them and impersonate legitimate users.
* Risk 3: **I/T** — Unencrypted traffic between the proxy and application can be intercepted or altered within the host or container environment.
* Risk 4: **T/E** — XSS can modify content executed in the browser and may lead to session hijacking or unauthorized actions.
* Risk 5: **S/R** — Without a defined identity store, the system cannot reliably demonstrate who authenticated or maintain a trustworthy audit trail.

### Trust Boundary Analysis

The communication path `User Browser -> Direct to App (no proxy) -> Juice Shop Application` crosses from the untrusted Internet boundary into the containerized application environment. This path is particularly attractive to attackers because it carries authentication and session information directly to the application. If HTTP remains in use, attackers may attempt to intercept or modify tokens before downstream security controls can inspect the request.

## Task 2: Hardened Variant and Comparison

### Security Improvements Implemented

* Updated direct browser-to-application communication from `http` to `https`.
* Replaced unauthenticated `http` communication between the reverse proxy and application with `https`, using `client-certificate` authentication and `technical-user` authorization.
* Retained outbound WebHook communication over `https` and explicitly documented it as an HTTPS POST request.
* Added a dedicated application-to-storage database connection secured with `sql-access-protocol-encrypted`.
* Configured persistent storage as encrypted using `data-with-symmetric-shared-key`.
* Documented the use of prepared statements, parameterized SQLite queries, and sanitized logging practices to prevent plaintext secrets from appearing in logs.
* Clarified that the browser processes and stores session and product information, eliminating model-noise findings related to unnecessary data transfers.

### Risk Comparison

| Severity  | Baseline | Secure |      Δ |
| --------- | -------: | -----: | -----: |
| Critical  |        0 |      0 |      0 |
| High      |        0 |      0 |      0 |
| Elevated  |        4 |      2 |     -2 |
| Medium    |       14 |     14 |      0 |
| Low       |        5 |      1 |     -4 |
| **Total** |   **23** | **17** | **-6** |

### Risks Eliminated in the Secure Variant

1. **missing-authentication** — Resolved by introducing authenticated communication between the reverse proxy and application using `client-certificate` authentication and `technical-user` authorization.
2. **unencrypted-communication** — Resolved by migrating browser and proxy communication to HTTPS and encrypting SQL-based storage access.
3. **unnecessary-data-transfer** — Resolved by explicitly specifying that the browser processes and stores the received session and catalog information.
4. **unnecessary-technical-asset** — Eliminated through the same browser data-asset clarification, meaning the browser is no longer modeled as an unused component.

### Risks Remaining in the Secure Variant

1. **cross-site-scripting** — Neither HTTPS nor storage encryption addresses input/output encoding weaknesses in a web application. The Juice Shop application still processes user-controlled input and therefore requires contextual output encoding, CSP, and server-side validation.
2. **sql-nosql-injection** — Although the model documents parameterized queries, Threagile continues to flag database access as a potential risk because the application communicates with a database via a SQL protocol. In practice, this risk would only be considered mitigated after code review and SAST verification confirm consistent use of parameterized queries.
3. **missing-vault** — Encrypting stored data does not provide a dedicated secrets-management solution. JWT signing keys, database credentials, and integration secrets would still require a vault or equivalent secret-storage mechanism.

### Validation of Results

No, the total number of risks was not reduced by more than 50%. The count decreased from 23 to 17, representing approximately a 26% reduction. While these security improvements effectively eliminate avoidable authentication and plaintext communication weaknesses, the remaining findings relate to deeper application and platform-level concerns that require code remediation, WAF/CSRF protections, secrets management, CI/CD modeling, and runtime hardening.

## Bonus Task: Authentication Flow Threat Model

### Risk Distribution

| Severity  |  Count |
| --------- | -----: |
| Critical  |      0 |
| High      |      0 |
| Elevated  |      5 |
| Medium    |     19 |
| Low       |      4 |
| **Total** | **28** |

### Three Authentication-Specific Risks Absent from the Baseline Top Five

1. **sql-nosql-injection** — STRIDE: **T/E** — The query path `Auth API -> Credential Store` could be exploited to manipulate credential lookup logic or bypass authentication mechanisms. Mitigation: enforce parameterized queries for all authentication-related lookups and introduce SAST/DAST testing focused on login and registration workflows.
2. **unguarded-access-from-internet** — STRIDE: **D/E** — The focused model indicates that both the Auth API and Admin API are directly accessible from the browser without a modeled protective layer. Mitigation: place a reverse proxy, WAF, or API gateway in front of these services, apply rate limiting to authentication endpoints, and enforce explicit authorization checks for administrative functions.
3. **missing-authentication-second-factor** — STRIDE: **S/E** — Relying solely on JWT-based access for administrative routes means that stolen credentials or tokens may be sufficient to gain privileged access. Mitigation: require MFA or step-up authentication for administrative operations and use short-lived admin tokens.

### Reflection

The focused authentication model revealed feature-specific security concerns that were less visible in the broader architectural model, particularly around database-backed credential validation, administrative JWT usage, and the absence of two-factor authentication for privileged operations. While the baseline model effectively highlights insecure communication channels and major architectural weaknesses, the authentication-focused model provides greater insight into how a seemingly valid token can become a focal point for spoofing and privilege-escalation attacks.
