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
1. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity **elevated**; affecting **juice-shop**
2. **missing-authentication** — Missing Authentication covering communication link *To App* from Reverse Proxy to Juice Shop Application; severity **elevated**; affecting **juice-shop**
3. **unencrypted-communication** — Unencrypted Communication named *Direct to App (no proxy)* between User Browser and Juice Shop Application transferring authentication data; severity **elevated**; affecting **user-browser**
4. **unencrypted-communication** — Unencrypted Communication named *To App* between Reverse Proxy and Juice Shop Application; severity **elevated**; affecting **reverse-proxy**
5. **container-baseimage-backdooring** — Container Base Image Backdooring risk at Juice Shop Application; severity **medium**; affecting **juice-shop**


### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **I, E** — XSS can steal user data and be executed with another user's privileges.
- Risk 2: **S, E** — an attacker can impersonate legitimate components and gain another's user privileges.
- Risk 3: **I** — without encryption, an attacker _(e.g. MITM)_ can steal user data.
- Risk 4: **I** — an attacker can read all traffic between the reverse proxy and the application.
- Risk 5: **T, E** — a backdoored container base image can be modified by an attacker, leading to malicious code execution and privilege escalation inside the application environment.

### Trust boundary observation
Looking at `data-flow-diagram.png`, name one arrow crossing a trust boundary that
appears in your top-5 risks. Why is that arrow particularly attractive to an attacker?

Looking at `data-flow-diagram.png`, the direct arrow from User Browser to Juice Shop Application appears in the top-5 risks above _(risk 4)_. The arrow is "particularly attractive to an attacker" since it is easy to steal sensitive user data _(passwords, credit card numbers, etc.)_: an attacker, being a transport node on the route between the user and the application _(e.g. ISP)_ can eavesdrop on the data.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | -3 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 19 | -4 |

### Which rules are GONE in the secure variant?
1. **missing-authentication** — fixed by changing `authentication: none` to `authentication: token` in technical asset **"Reverse Proxy"**, communication link **"To App"**.
2. **unencrypted-communication** _(Reverse Proxy to App)_ — fixed by changing `protocol: http` to `protocol: https` in technical asset **"Reverse Proxy"**, communication link **"To App"**.
3. **unencrypted-communication** _(Direct to App (no proxy))_ — fixed by changing `protocol: http` to `protocol: https` in technical asset **"User Browser"**, communication link **"Direct to App (no proxy)"**.

### Which rules are STILL THERE in the secure variant?
1. **cross-site-scripting** — the risk remains because the implemented changes focused on transport security, encryption, and secure communication links, not on eliminating application-layer input validation flaws. OWASP Juice Shop is intentionally vulnerable by design, so user-supplied content may still be rendered in a way that allows malicious JavaScript execution. Security headers and TLS reduce the impact of some attacks but do not completely prevent XSS vulnerabilities in the application code.

2. **container-baseimage-backdooring** — the risk remains because the threat model still relies on a Docker container image whose supply chain is outside the scope of the implemented mitigations. Encrypting data, enforcing HTTPS, and securing network communication do not verify the integrity or trustworthiness of the container base image itself. A compromised or malicious base image could still introduce backdoors into the application environment before deployment.

### Honesty check
The total number of risks dropped by approximately 17.39% (from 23 to 19). The implemented hardening measures primarily addressed transport and storage security concerns, while the remaining findings are mostly related to application-level vulnerabilities and software supply-chain risks that require secure coding practices, stronger input validation, dependency management, and image provenance controls. Despite the relatively small reduction in the total risk count, the changes were effective in removing 3 of the 4 elevated-severity risks, indicating a favorable security improvement for a comparatively low implementation effort.

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 18 |
| Medium | 12 |
| Low | 1 |
| **Total** | 32 |

### Three auth-specific risks (NOT in the baseline model's top 5)
1. **missing-identity-provider-isolation** — STRIDE: E — Mitigation: Place the Token Signer into a dedicated network segment and allow access only from the trusted services.
2. **missing-vault** — STRIDE: E — Mitigation: Store JWT signing keys in a dedicated Vault or use a Secret Manager.
3. **missing-identity-store** — STRIDE: S — Mitigation: Implement a dedicated identity store. 

### Reflection
The focused model revealed authentication-specific risks that were not visible in the baseline architecture model, such as missing identity provider isolation, lack of secure vault for JWT signing keys, and absence of a dedicated identity store.

By decomposing authentication into concrete components _(`JWT token`, `User Session state`, `Admin operation requests`, etc.)_, the model introduced explicit trust boundaries and data flows. This allowed Threagile to detect implementation-level risks related to token handling and identity management that are not apparent in a high-level architectural view.