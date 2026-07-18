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
1. **unencrypted-communication** — Direct to App (no proxy); severity elevated; affecting user-browser
2. **unencrypted-communication** — To App (via Reverse Proxy); severity elevated; affecting reverse-proxy
3. **missing-authentication** — To App (via Reverse Proxy); severity elevated; affecting juice-shop
4. **cross-site-scripting** — XSS risk at Juice Shop; severity elevated; affecting juice-shop
5. **unnecessary-data-transfer** — Tokens & Sessions; severity low; affecting user-browser

### STRIDE mapping
- Risk 1: **I (Information Disclosure)** — Unencrypted HTTP allows attackers to intercept authentication data in transit.
- Risk 2: **I (Information Disclosure)** — Internal traffic between proxy and app is unencrypted, risking data interception.
- Risk 3: **E (Elevation of Privilege)** — Missing authentication on internal links allows unauthorized access to the app.
- Risk 4: **T (Tampering)** — XSS allows attackers to modify page content and steal user data.
- Risk 5: **I (Information Disclosure)** — Sending unnecessary tokens increases the attack surface for data theft.

### Trust boundary observation
Arrow: User Browser (Internet) -> Juice Shop Application (Container).
Why attractive: It crosses the main trust boundary from the untrusted internet directly to the app without encryption (HTTP), making it the easiest target for Man-in-the-Middle attacks to steal credentials.



## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 5 | +1 |
| Medium | 14 | 14 | 0 |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 24 | +1 |

### Which rules are GONE in the secure variant?
1. `unencrypted-communication` (Reverse Proxy to App) — fixed by changing protocol from http to https
2. `insecure-data-storage` (Persistent Storage) — fixed by adding encryption: data-with-symmetric-shared-key
3. `missing-transport-layer-encryption` (WebHook) — already was https, no change needed

### Which rules are STILL THERE in the secure variant?
1. `missing-authentication` — Still present because we only encrypted communication but didn't add authentication middleware to protect endpoints. The Reverse Proxy to App link still has `authentication: none`.
2. `cross-site-scripting` — XSS vulnerability remains because encrypting transport doesn't fix input validation issues in the application code. This requires code-level changes, not just configuration.

### Honesty check
Did the total drop more than 50%? No, it actually increased by 1 (23 → 24).
This happened because I added two new communication links (To Database and To Logging) to demonstrate prepared statements and encrypted logging, which introduced new risks. The encryption changes fixed some risks but the new links created others. To truly reduce risks, I would need to add authentication to the new links and ensure all security requirements are declared. This shows that threat modeling is iterative — each change needs to be carefully evaluated to avoid introducing new vulnerabilities while fixing old ones.



## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 3 |
| Medium | 19 |
| Low | 6 |
| **Total** | 28 |

### Three auth-specific risks (NOT in the baseline model's top 5)
1. **sql-nosql-injection** — STRIDE: T (Tampering) — Mitigation: Use parameterized queries in auth-api when checking credentials against user-db to prevent SQL injection attacks that could bypass authentication.
2. **missing-authentication** (auth-api-to-token-signer) — STRIDE: E (Elevation of Privilege) — Mitigation: Add authentication between auth-api and token-signer to prevent unauthorized components from requesting JWT tokens on behalf of users.
3. **missing-authentication** (browser-to-auth-api) — STRIDE: S (Spoofing) — Mitigation: Implement proper authentication checks on the login endpoint to prevent attackers from impersonating users or brute-forcing credentials without rate limiting.

### Reflection (2-3 sentences)
Building the focused auth model revealed risks specific to the authentication flow that the baseline architecture model missed, such as SQL injection in the credential verification path and missing authentication between internal auth components. Feature-level threat models provide deeper insights into specific workflows, while architecture-level models give a broader but shallower view. The auth model showed that even with HTTPS encryption, application-level vulnerabilities like SQL injection and missing authentication remain critical attack vectors that require code-level fixes.
