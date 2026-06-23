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
1. **`unencrypted-communication`** - Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity elevated; affecting Reverse Proxy / Juice Shop Application
2. **`unencrypted-communication`** - Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data; severity elevated; affecting User Browser / Juice Shop Application
3. **`missing-authentication`** - Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity elevated; affecting Juice Shop Application
4. **`cross-site-scripting`** - Cross-Site Scripting (XSS) risk at Juice Shop Application; severity elevated; affecting Juice Shop Application
5. **`missing-vault`** - Missing Vault (Secret Storage) in the threat model; severity medium; affecting Juice Shop Application

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **I (Information Disclosure)** - Lack of encryption exposes sensitive data in transit to network sniffing, violating confidentiality.
- Risk 2: **S (Spoofing) & I (Information Disclosure)** - Missing HTTPS allows attackers to intercept session tokens in plaintext and spoof the legitimate user's identity.
- Risk 3: **S (Spoofing)** - Without mutual authentication, an internal attacker can bypass the proxy and send direct requests to the app, spoofing a trusted component.
- Risk 4: **S (Spoofing)** - XSS allows an attacker to execute malicious scripts in the victim's browser and steal session cookies, leading to identity spoofing.
- Risk 5: **I (Information Disclosure)** - Hardcoding or improperly storing secrets without a secure vault violates confidentiality, exposing keys to anyone with environment access.

### Trust boundary observation
Looking at `data-flow-diagram.png`, name one arrow crossing a trust boundary that appears in your top-5 risks. Why is that arrow particularly attractive to an attacker?
The arrow originating from the **User Browser** (Internet trust boundary) and crossing into the **Container Network** (Juice Shop Application) is highly attractive to attackers. It represents the primary exposed attack surface designed to accept untrusted external input, making it the most accessible entry point to exploit application vulnerabilities like XSS or intercept unencrypted authentication data.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 4 | 0 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 4 | -1 |
| **Total** | 23 | 21 | -2 |

### Which rules are GONE in the secure variant?
List 3 rule IDs that fired in baseline but not in secure-variant:
1. `unencrypted-communication` (Direct to App) - fixed by changing `protocol: http` to `protocol: https` on the browser-to-app link.
2. `unencrypted-communication` (Reverse Proxy to App) - fixed by changing the internal hop `protocol: http` to `protocol: https` between proxy and app.
3. `unencrypted-asset` (Juice Shop App logs) - fixed by setting `encryption: data-with-symmetric-shared-key` on the Juice Shop Application technical asset to protect stored logs.

### Which rules are STILL THERE in the secure variant?
Threat modeling never reaches zero risk. List 2 rules that still fire and explain why
your changes didn't eliminate them (2-3 sentences each).

1. `cross-site-scripting` - This rule still fires because XSS is an application-level flaw caused by improper input sanitization and output encoding. My hardening changes (enabling HTTPS and encrypting logs) only secured the transport and storage layers, leaving the core application logic just as vulnerable to malicious scripts.
2. `missing-authentication` - The proxy-to-app link still lacks mutual authentication. Even though I encrypted the channel with HTTPS, the Juice Shop application still blindly trusts any incoming connection on that port without cryptographically verifying if it actually originated from the authorized Reverse Proxy.

### Honesty check
Did the total drop more than 50%? If yes, what does that say about the cost-benefit
of these particular hardening changes vs. the work you'd need to fully eliminate the rest?
No, the total dropped by less than 10% (from 23 to 21 risks). This shows that infrastructure-level hardening (like enabling TLS or encrypting storage volumes) is relatively cheap and easy to implement, but it does not fix the bulk of the threat landscape. Eliminating the remaining risks requires significantly more expensive and time-consuming engineering work, such as rewriting vulnerable application code (for XSS), implementing proper identity verification, and adopting a dedicated secrets vault.

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 7 |
| Medium | 14 |
| Low | 3 |
| **Total** | 25 |

### Three auth-specific risks (NOT in the baseline model's top 5)

1. **missing-authentication** — STRIDE: S (Spoofing) — Mitigation: Enforce mutual TLS (mTLS) or internal service-to-service API keys between the `auth-api` and the `token-signer` so that the signer only accepts JWT generation requests from trusted internal services.
2. **sql-nosql-injection** — STRIDE: T (Tampering) & I (Information Disclosure) — Mitigation: Ensure the `auth-api` uses strongly typed ORMs or strictly parameterized queries when querying the `user-db` for user credentials during the login process.
3. **server-side-request-forgery** — STRIDE: E (Elevation of Privilege) — Mitigation: Implement strict allow-listing for outbound network calls from the `auth-api` container, ensuring it can only reach the exact internal IP/port of the `token-signer` and not arbitrary internal network addresses.

### Reflection
What did building the focused model surface that the baseline architecture model missed?
Building a feature-level model exposed the internal micro-component interactions within the auth flow itself (like the `token-signer` and internal API calls), which were completely abstracted away in the high-level architecture model. This allowed Threagile to flag critical internal trust issues (like missing authentication between internal microservices) that would have otherwise gone unnoticed.
