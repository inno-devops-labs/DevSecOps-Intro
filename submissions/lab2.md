## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|------:|
| Critical |     0 |
| High |     0 |
| Elevated |     4 |
| Medium |    14 |
| Low |     5 |
| **Total** |     23 |

### Top 5 risks (paste from `jq` output)
1. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity elevated; affecting juice-shop
2. **missing-authentication** — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity elevated; affecting juice-shop
3. **unencrypted-communication** — Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data (like credentials, token, session-id, etc.); severity elevated; affecting user-browser
4. **unencrypted-communication** — Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity elevated; affecting reverse-proxy
5. **unnecessary-technical-asset** — Unnecessary Technical Asset named Persistent Storage; severity low; affecting persistent-storage

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **T I** — XSS allows attacker to steal session cookies (disclosure) and modify page content (tampering) in victim's browser
- Risk 2: **S** — missing authentication on the communication link allows an attacker to represent a legitimate user or a system component without verifying identity
- Risk 3: **I** — lack of encryption exposes authentication tokens and sensitive data to network sniffing
- Risk 4: **I** —  internal traffic could be intercepted by a compromised container or host
- Risk 5: **D** — affecting persistent-storage
### Trust boundary observation
Looking at `data-flow-diagram.png`, name one arrow crossing a trust boundary that
appears in your top-5 risks. Why is that arrow particularly attractive to an attacker?
    User Browser → Juice Shop Application throw HTTP. This arrow is attractive because it represents external user input entering the application. Attackers can exploit this entry point to perform injection or authentication attacks.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure |  Δ |
|----------|---------:|-------:|---:|
| Critical |        0 |      0 |  0 |
| High |        0 |      0 |  0 |
| Elevated |        4 |      3 | -1 |
| Medium |       14 |     13 | -1 |
| Low |        5 |      5 |  0 |
| **Total** |       23 |     21 | -2 |

### Which rules are GONE in the secure variant?
List 3 rule IDs that fired in baseline but not in secure-variant:
1. `Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data (like credentials, token, session-id, etc.)
` — fixed by enforcing HTTP to HTTPS in the communication link between User Browser and Juice Shop Application
2. `Unencrypted Technical Asset named Persistent Storage` — fixed by enabling encryption at rest using a data-with-symmetric-shared-key
Only 2 risks disappeared because some recommended controls were already present in the baseline model and some was overlap by effect.
### Which rules are STILL THERE in the secure variant?
Threat modeling never reaches zero risk. List 2 rules that still fire and explain why
your changes didn't eliminate them (2-3 sentences each).
- Unnecessary Technical Asset named Persistent Storage:
This risk remains because the presence of persistent storage itself was not removed or justified in the model. While encryption at rest was enabled, the asset may still be considered unnecessary from an architectural perspective. 

- Missing Web Application Firewall (WAF) risk at Juice Shop Application:
This risk persists because no WAF or similar protective layer was added in the secure variant. The changes focused on encryption and secure communication, but did not introduce additional defensive controls against web-based attacks. 
### Honesty check
Did the total drop more than 50%? If yes, what does that say about the cost-benefit
of these particular hardening changes vs. the work you'd need to fully eliminate the rest?
No, the total drop not more than 50%. This indicates that while basic hardening measures are relatively easy to implement and provide quick improvements, eliminating the remaining risks would require significantly more effort.

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical |     0 |
| High |     0 |
| Elevated |     4 |
| Medium |     7 |
| Low |    11 |
| **Total** |    22 |

### Three auth-specific risks (NOT in the baseline model's top 5)
For each, name:
- The rule ID Threagile fires
- The STRIDE letter
- A 1-2 sentence mitigation in plain English

1. **cross-site-scripting** — STRIDE: T — Mitigation: Validate and purify all user inputs and encode output in the browser. Additionally, implement Content Security Policy headers to reduce the impact of XSS attacks.
2. **missing-vault** — STRIDE: I — Mitigation: Store sensitive secrets in a dedicated secrets management system instead of storing them in plain storage.
3. **container-base-image-backdooring** — STRIDE: T — Mitigation: Use trusted and minimal base images, regularly scan them for vulnerabilities, and pin image versions.

### Reflection (2-3 sentences)
What did building the focused model surface that the baseline architecture model missed?
(Hint: feature-level threat models often find what architecture-level ones can't.)

Building the focused authentication model surfaced specific authorization, token-handling risks, privilege escalation paths, missing JWT verification and insecure JWT signing key transmission that the baseline architecture model missed. The baseline model treated authentication as a black box and couldn't detect token-handling logic flaws. Only the feature-level model showed that internal service-to-service communication lacks encryption and role-based access control checks.

