## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|------:|
| Critical |  0  |
| High     |  0  |
| Elevated |  4  |
| Medium   |  5  |
| Low      |  14 |
| Total    |  23 |

### Top 5 risks (paste from `jq` output)
1. missing-authentication — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity elevated; affecting juice-shop
2. unencrypted-communication — Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data such as credentials, tokens, or session IDs; severity elevated; affecting user-browser
3. unencrypted-communication — Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity elevated; affecting reverse-proxy
4. cross-site-scripting — Cross-Site Scripting risk at Juice Shop Application; severity elevated; affecting juice-shop
5. unencrypted-asset — Unencrypted Technical Asset named Juice Shop Application; severity medium; affecting juice-shop

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **<S/T/R/I/D/E>** — <why, 1 sentence>
- Risk 2: ...

### Trust boundary observation
The User Browser → Juice Shop Application flow, named Direct to App, crosses a trust boundary from the Internet/user-controlled zone into the application/container zone.

This flow is particularly attractive to an attacker because it is directly reachable from outside the system and transfers authentication-sensitive data. Since it bypasses the reverse proxy, the attacker may also bypass TLS termination, security headers, and other proxy-level protections.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical |    0     |   0    | 0 |
| High     |    0     |   0    | 0 |
| Elevated |    4     |   1    | 3 |
| Medium   |    5     |   5    | 0 |
| Low      |    14    |   12   | 2 |
| Total    |    23    |   18   | 5 |

### Which rules are GONE in the secure variant?

1. `missing-authentication` — fixed by declaring authentication on the internal **Reverse Proxy → Juice Shop Application** communication link.
2. `unencrypted-asset` — fixed by changing the relevant technical asset/storage encryption from `none` to an encrypted/transparent storage option in the secure variant.
3. `unencrypted-communication` — fixed by changing insecure communication links from `http` to `https`, especially for the **Direct to App (no proxy)** and internal app traffic flows.

### Which rules are STILL THERE in the secure variant?

1. `cross-site-scripting` — This risk still fires because HTTPS and encrypted storage do not eliminate application-level XSS issues. Removing this risk would require code-level and browser-side mitigations, such as output encoding, input validation, safe template rendering, and a strict Content Security Policy.

2. `missing-waf` — This risk still exists because the secure variant improves transport encryption, storage encryption, and authentication declarations, but it does not add a Web Application Firewall in front of Juice Shop. Eliminating it would require adding and modeling a WAF layer, for example ModSecurity/Coraza or a managed WAF, with rules for common web attacks.

### Honesty check

No, the total risk count did not drop more than 50%. The baseline model had **23** risks, while the secure variant has **18** risks, so the drop is **5** risks, or **21.74%**.

This shows that the selected hardening changes are still useful: a small number of architectural changes removed several important risks related to missing authentication, unencrypted assets, and unencrypted communication. However, the remaining findings show that threat modeling does not reach zero risk through simple configuration changes alone. The rest would require deeper controls such as WAF integration, application hardening, CSRF/XSS protections, identity-store improvements, vault/secret management, and build infrastructure security.

## Bonus Task: Auth Flow Threat Model

### Risk count

| Severity  | Count |
| --------- | ----: |
| Critical  |   0   |
| High      |   0   |
| Elevated  |   5   |
| Medium    |   13  |
| Low       |   5   |
| Total     |   23  |

### Three auth-specific risks (NOT in the baseline model's top 5)

1. **missing-authentication-second-factor** — STRIDE: **S / E** — Mitigation: Require MFA for admin users and other privileged operations. This makes stolen credentials or a stolen JWT less useful for impersonation and privilege escalation.

2. **missing-vault** — STRIDE: **I / S / E** — Mitigation: Store JWT signing keys and other authentication secrets in a dedicated vault or secret-management system. Access to the signing key should be restricted, audited, and rotated so that compromise of one application container does not immediately allow token forgery.

3. **sql-nosql-injection** — STRIDE: **T / E** — Mitigation: Use parameterized queries or ORM-safe methods when the Auth API checks credentials in the User Store. Login input must be validated and never concatenated into SQL/NoSQL queries, because injection in the authentication path can lead to account bypass or role manipulation.

### Reflection

Building the focused auth-flow model surfaced risks that the baseline architecture model did not show in its top findings. The baseline model mostly highlighted broad architecture issues such as unencrypted communication, missing authentication between components, XSS, and unencrypted assets.

The auth-specific model made the login path, JWT issuance, JWT verification, credential store, signing key, and admin endpoint explicit. This made it easier to see spoofing and elevation-of-privilege risks around stolen tokens, missing MFA, weak secret storage, and injection in the credential-checking flow.

