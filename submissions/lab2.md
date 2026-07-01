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
1. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity elevated; affecting juice-shop
2. **unencrypted-communication** — Unencrypted Communication named Direct to App (no proxy); severity elevated; affecting user-browser
3. **unencrypted-communication** — Unencrypted Communication named To App; severity elevated; affecting reverse-proxy
4. **missing-authentication** — Missing Authentication covering communication link To App; severity elevated; affecting juice-shop
5. **unnecessary-technical-asset** — Unnecessary Technical Asset named Persistent Storage; severity low; affecting persistent-storage

### STRIDE mapping
- Risk 1 (XSS): **S, T (Spoofing, Tampering)** — Attackers can execute arbitrary scripts in a victim's browser, hijacking sessions or modifying content.
- Risk 2 (Unencrypted Comms - Direct): **I, D (Information Disclosure, Tampering)** — Traffic over HTTP directly to the app can be intercepted or manipulated in transit by a Man-in-the-Middle.
- Risk 3 (Unencrypted Comms - Proxy to App): **I, D (Information Disclosure, Tampering)** — Internal traffic between the proxy and the app is unencrypted, vulnerable to internal network sniffing.
- Risk 4 (Missing Auth - Proxy to App): **S, E (Spoofing, Elevation of Privilege)** — The internal link lacks identity verification, potentially allowing bypass if the network is breached.
- Risk 5 (Unnecessary Asset): **I, D, E (Information Disclosure, Tampering, Elevation)** — Having an unused but persistent asset increases the attack surface for potential exploitation or data leakage.

### Trust boundary observation
Looking at the data flow, the arrow connecting the **Internet** trust boundary to the **Execution Environment** (User Browser -> Juice Shop Application) is highly attractive to an attacker. This is the primary attack surface where external, untrusted user inputs enter the application, making it the ideal vector for XSS and Auth bypasses.

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
1. `unencrypted-communication` — fixed by changing the protocol from http to https for the Reverse Proxy to App connection.
2. `unencrypted-asset` — fixed by setting the persistent-storage database encryption to `data-with-symmetric-shared-key`.
3. `sql-injection` — fixed by documenting the use of parameterized queries and prepared statements in the Juice Shop application's description.

### Which rules are STILL THERE in the secure variant?
1. `missing-web-application-firewall` — Modifying internal app protocols and database encryption does not provide a WAF at the network perimeter.
2. `cross-site-scripting` — Infrastructure changes (like HTTPS or DB encryption) do not fix application-layer vulnerabilities related to input sanitization.

### Honesty check
The total risk dropped from 23 to 20. While it didn't drop by more than 50% in total volume, we successfully eliminated specific structural and architectural risks (like cleartext internal traffic and unencrypted data at rest) with just a few lines of configuration. This shows that infrastructure-as-code hardening offers a high ROI for architectural flaws, but application-layer bugs (like XSS) still require manual code-level fixes, which is why the total count remains relatively high.

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 5 |
| Medium | 18 |
| Low | 3 |
| **Total** | 27 |

### Three auth-specific risks (NOT in the baseline model's top 5)
1. **missing-vault** (High) — STRIDE: Information Disclosure — Mitigation: Store the `jwt_key` in a secure secret manager (like HashiCorp Vault) rather than as a local process environment variable or file.
2. **missing-hardening** (Elevated) — STRIDE: Elevation of Privilege — Mitigation: Apply strict runtime hardening and AppArmor/Seccomp profiles to the `auth-api` and `user-db` containers to prevent lateral movement if the auth logic is bypassed.
3. **missing-identity-provider-isolation** (Medium) — STRIDE: Spoofing/Elevation — Mitigation: Offload authentication to a dedicated, isolated OIDC/SAML provider rather than handling custom credential verification in the main application backend.

### Reflection
Building a focused authentication model surfaced specific cryptographic and identity risks (like `missing-vault` for the JWT signing key) that got lost in the noise of the main architecture diagram. This proves that feature-level threat models are absolutely necessary for identifying logic abuse cases that high-level infrastructure models miss.
