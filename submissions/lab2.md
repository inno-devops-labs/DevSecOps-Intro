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
1. **unencrypted-communication** — Unencrypted Communication (Direct to App, no proxy) between User Browser and Juice Shop Application transferring auth data; severity: elevated; affecting: user-browser
2. **unencrypted-communication** — Unencrypted Communication (To App) between Reverse Proxy and Juice Shop Application; severity: elevated; affecting: reverse-proxy
3. **missing-authentication** — Missing Authentication covering link "To App" from Reverse Proxy to Juice Shop Application; severity: elevated; affecting: juice-shop
4. **cross-site-scripting** — XSS risk at Juice Shop Application; severity: elevated; affecting: juice-shop
5. **unnecessary-data-transfer** — Unnecessary Data Transfer of Tokens & Sessions from/to User Browser ↔ Juice Shop Application; severity: low; affecting: user-browser

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **T** (Tampering) — the unencrypted channel between User Browser and Juice Shop allows an attacker to intercept and modify credentials or session tokens in transit via MitM attack
- Risk 2: **T** (Tampering) — HTTP traffic between Reverse Proxy and Juice Shop Application can be intercepted and altered by an insider or compromised internal node
- Risk 3: **S** (Spoofing) — without authentication on the internal "To App" link, any process on the same network can impersonate a legitimate client to Juice Shop
- Risk 4: **T** (Tampering) — XSS enables an attacker to inject malicious scripts that alter page behaviour and steal session data on behalf of the victim
- Risk 5: **I** (Information Disclosure) — unnecessary transfer of Tokens & Sessions data to the User Browser expands the attack surface for token leakage

### Trust boundary observation
Looking at `data-flow-diagram.png`, name one arrow crossing a trust boundary that
appears in your top-5 risks. Why is that arrow particularly attractive to an attacker?

The arrow **User Browser → Juice Shop Application** crosses the Internet → Container trust boundary.
This link is particularly attractive to an attacker because it carries authentication data (credentials, tokens, session IDs) over unencrypted HTTP — a single MitM position on the network is enough to capture valid session tokens and fully compromise any user account without exploiting any application vulnerability.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High     | 0 | 0 | 0 |
| Elevated | 4 | 2 | -2 |
| Medium   | 14 | 13 | -1 |
| Low      | 5 | 5 | 0 |
| **Total**| **23** | **20** | **-3** |

### Which rules are GONE in the secure variant?
1. `unencrypted-communication` — fixed by changing protocol: http → https on user-facing and internal links
2. `missing-authentication` — fixed by enforcing https which improved the authentication posture on internal links
3. `unencrypted-asset` — fixed by adding encryption: data-with-symmetric-shared-key to Persistent Storage

### Which rules are STILL THERE in the secure variant?
1. `cross-site-scripting` — XSS is an application-level vulnerability; changing transport
   protocol or storage encryption has no effect on how the app handles user-supplied
   input in the DOM. It requires input validation and output encoding fixes in the code.
2. `missing-hardening` — hardening flags (security headers, rate limiting, CSP) are
   declared as missing at the application layer; switching to HTTPS does not
   automatically enable these controls since they must be explicitly configured.

### Honesty check
The total dropped by only 13% (23 → 20), which is less than 50%. This shows that
transport and storage hardening alone eliminates only a small fraction of risks.
The majority of remaining findings are application-level issues (XSS, CSRF, missing
hardening, missing WAF) that require actual code changes, infrastructure additions,
or configuration work — meaning the cost of fully eliminating risks is significantly
higher than the few field changes made here.
