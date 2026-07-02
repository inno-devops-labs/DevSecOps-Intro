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
1. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity elevated; affecting juice-shop
2. **unencrypted-communication** — Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data; severity elevated; affecting user-browser
3. **unencrypted-communication** — Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity elevated; affecting reverse-proxy
4. **missing-authentication** — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity elevated; affecting juice-shop
5. **missing-waf** — Missing Web Application Firewall (WAF) risk at Juice Shop Application; severity low; affecting juice-shop

### STRIDE mapping (Lecture 2 slide 7)
- Risk 1: **S (Spoofing) / I (Information Disclosure)** — An attacker can inject malicious scripts into the application to steal user session tokens or spoof actions on behalf of the victim.
- Risk 2: **I (Information Disclosure)** — Transferring authentication data over an unencrypted HTTP link exposes credentials to network eavesdropping and Man-in-the-Middle (MitM) attacks.
- Risk 3: **I (Information Disclosure)** — Lack of encryption on internal traffic between the reverse proxy and the application allows lateral attackers to sniff sensitive data in transit.
- Risk 4: **S (Spoofing) / E (Elevation of Privilege)** — If an attacker bypasses the reverse proxy, they can directly interact with the backend application without authentication, spoofing requests.
- Risk 5: **T (Tampering) / D (Denial of Service)** — Without a WAF filtering malicious incoming traffic, the application is directly exposed to automated tampering payloads and application-layer DoS attacks.

### Trust boundary observation
The communication link "Direct to App (no proxy)" from the **User Browser** to the **Juice Shop Application** crosses the trust boundary from the completely untrusted public Internet into the application environment. This arrow is particularly attractive to an attacker because it represents the primary, publicly accessible attack surface that can be probed globally without requiring prior internal network compromise.

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
1. `unencrypted-communication` (User Browser to Juice Shop) — fixed by enforcing `https` protocol on the public communication link.
2. `unencrypted-communication` (Reverse Proxy to Juice Shop) — fixed by enforcing `https` on the internal backend link.
3. `unencrypted-asset` (or similar missing at-rest protection) — fixed by applying `data-with-symmetric-shared-key` encryption to the Persistent Storage.

### Which rules are STILL THERE in the secure variant?
1. `cross-site-scripting` — Architectural hardening (like TLS and encrypted disks) does not fix application-layer vulnerabilities in the source code.
2. `missing-waf` — We did not introduce a Web Application Firewall component into the trust boundary to filter malicious payloads.

### Honesty check
Did the total drop more than 50%? **No.** The total risk count only dropped from 23 to 20 (a ~13% reduction). 
If yes, what does that say about the cost-benefit of these particular hardening changes vs. the work you'd need to fully eliminate the rest? 
*Answer:* This demonstrates a classic security reality. Infrastructure hardening (TLS, encrypted volumes) is quick to implement but only stops network sniffing and physical disk theft. It does absolutely nothing against the application-layer flaws (OWASP Top 10) that make up the vast majority of Juice Shop's attack surface. To eliminate the rest, significant effort is required in SAST/DAST scanning and actual code refactoring.

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Elevated | 6 |
| Medium | 20 |
| Low | 10 |
| **Total** | 36 |

### Three auth-specific risks
1. **unguarded-access-from-internet** (Auth API / Login Link) — STRIDE: **E** (Elevation of Privilege) / **S** (Spoofing) — Mitigation: Implement strict rate limiting, CAPTCHA, or account lockouts to prevent brute-force attacks on the exposed login endpoint.
2. **cross-site-request-forgery** (Admin API via Admin Access Link) — STRIDE: **S** (Spoofing) — Mitigation: Enforce strict SameSite cookie policies for session tokens and require anti-CSRF tokens for all state-changing administrative requests.
3. **missing-authentication-second-factor** (Admin Access Link) — STRIDE: **E** (Elevation of Privilege) — Mitigation: Require Multi-Factor Authentication (MFA/2FA) for any user role attempting to access the highly privileged Admin API.

### Reflection
What did building the focused model surface that the baseline architecture model missed?
*Answer:* The focused model surfaced deep logical and protocol-level vulnerabilities (like CSRF and the lack of MFA for admin endpoints) that were completely obscured in the baseline model. Architecture-level models highlight infrastructure flaws (like missing TLS), but feature-level models are required to identify business logic and authentication weaknesses.
