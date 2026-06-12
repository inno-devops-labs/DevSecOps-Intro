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

### Top 5 risks (from risks.json)
1. **unencrypted-communication@user-browser>direct-to-app-no-proxy** — Unencrypted Communication (Direct to App); severity **Elevated**; exploitation Likely/High; affecting user-browser → juice-shop
2. **unencrypted-communication@reverse-proxy>to-app** — Unencrypted Communication (To App); severity **Elevated**; exploitation Likely/Medium; affecting reverse-proxy → juice-shop
3. **missing-authentication@reverse-proxy>to-app** — Missing Authentication; severity **Elevated**; exploitation Likely/Medium; affecting juice-shop
4. **cross-site-scripting@juice-shop** — Cross-Site Scripting (XSS); severity **Elevated**; exploitation Likely/Medium; affecting juice-shop
5. **container-baseimage-backdooring@juice-shop** — Container Base Image Backdooring; severity **Medium**; exploitation Unlikely/Medium; affecting juice-shop

### STRIDE mapping (Lecture 2 slide 7)
1. **unencrypted-communication (Direct to App)** — **I** (Information Disclosure) — HTTP traffic transfers authentication data (tokens, credentials) in plaintext, allowing network attackers to eavesdrop
2. **unencrypted-communication (proxy→app)** — **I** (Information Disclosure) — Internal proxy-to-app communication lacks encryption, exposing session tokens and product data
3. **missing-authentication** — **E** (Elevation of Privilege) — Reverse proxy forwards requests to Juice Shop without authentication, allowing unauthenticated access to sensitive data
4. **cross-site-scripting** — **T** (Tampering) — XSS allows attackers to inject malicious scripts that steal/modify user sessions and data
5. **container-baseimage-backdooring** — **T** (Tampering) — Compromised base images allow persistent code execution in deployed containers

### Trust boundary observation
The arrow **User Browser → Juice Shop Application** (Direct to App, HTTP on port 3000) crosses the trust boundary from **Internet** to **Container Network**. This arrow is particularly attractive because:
- It transfers authentication data (Tokens & Sessions) in **plaintext** over HTTP
- It's marked as **Elevated** risk with **Likely** exploitation and **High** impact
- Any network attacker on the same network can perform MITM attacks to steal user credentials and session tokens
- Juice Shop Application has RAA of 70%, making it a high-value target

---

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 2 | **-2** |
| Medium | 14 | 13 | **-1** |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 20 | **-3** |

### Which rules are GONE in the secure variant?
1. **unencrypted-communication@reverse-proxy>to-app** — Fixed by changing protocol from `http` to `https` for the proxy→app communication link
2. **missing-authentication@reverse-proxy>to-app** — Fixed by adding `authentication: session-id` and `authorization: enduser-identity-propagation` to the proxy→app link
3. **unencrypted-asset@persistent-storage** — Fixed by adding `encryption: data-with-symmetric-shared-key` to the Persistent Storage technical asset

### Which rules are STILL THERE in the secure variant?
1. **cross-site-scripting@juice-shop** — My changes only addressed transport security (HTTPS) and storage encryption. XSS is an **application-level vulnerability** that requires input validation, output encoding, and CSP headers. Transport encryption doesn't prevent malicious script injection in the application code.

2. **unencrypted-communication@user-browser>direct-to-app-no-proxy** — This risk remains because the "Direct to App (no proxy)" communication link still uses HTTP. In a real deployment, you would either disable direct access entirely (force all traffic through the reverse proxy) or also upgrade this link to HTTPS. The model keeps both paths for architectural flexibility, so the direct path remains a risk.

3. **missing-hardening@juice-shop** and **missing-hardening@persistent-storage** — Hardening is an operational concern (CIS benchmarks, vendor guides) that cannot be expressed through YAML model fields. These risks require actual configuration work outside the threat model.

### Honesty check
Total dropped from 23 to 20 risks (13% reduction, **not** 50%). This shows that **infrastructure hardening** (HTTPS, encryption at rest, authentication on internal links) addresses only a small subset of risks. The remaining 20 risks require:
- **Application-level fixes** (XSS prevention, CSRF tokens, input validation) — 3 risks
- **Architecture changes** (adding identity store, vault, build infrastructure) — 3 risks
- **Operational controls** (WAF, 2FA, hardening guides, container image scanning) — 10 risks
- **Model completeness** (removing unnecessary assets, adding missing components) — 4 risks

This demonstrates **defense-in-depth**: transport security is necessary but insufficient. You need layered security controls across infrastructure, application, and operations. The cost-benefit analysis shows that infrastructure hardening is relatively cheap (configuration changes) but only addresses 13% of risks. Full mitigation requires expensive application rewrites, architectural changes, and operational processes.

---

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 5 |
| Medium | 16 |
| Low | 11 |
| **Total** | 32 |

### Three auth-specific risks (NOT in the baseline model's top 5)

The baseline top-5 risks were:
1. unencrypted-communication@user-browser>direct-to-app-no-proxy (Elevated)
2. unencrypted-communication@reverse-proxy>to-app (Elevated)
3. missing-authentication@reverse-proxy>to-app (Elevated)
4. cross-site-scripting@juice-shop (Elevated)
5. container-baseimage-backdooring@juice-shop (Medium)

### Reflection

Building the focused auth model surfaced implementation-level risks like SQL injection and unguarded admin access that the baseline architecture model missed because it treated authentication as a black box. This confirms that feature-level threat models are essential for revealing application-layer flaws, while architecture-level models are better suited for catching infrastructure risks. Ultimately, this shows that effective threat modeling must be iterative, combining both macro and micro views to achieve true defense-in-depth.
