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
2. **missing-authentication** — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity elevated; affecting juice-shop
3. **unencrypted-communication** — Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data (like credentials, token, session-id, etc.); severity elevated; affecting user-browser
4. **unencrypted-communication** — Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity elevated; affecting reverse-proxy
5. **unnecessary-technical-asset** — Unnecessary Technical Asset named Persistent Storage; severity low; affecting persistent-storage

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1 (XSS): **T (Tampering)** — The application allows an attacker to inject and execute malicious scripts, altering the legitimate webpage behavior for other users.
- Risk 2 (Missing Auth): **S (Spoofing)** — The lack of authentication on the reverse proxy link allows an attacker to easily impersonate a legitimate user or internal service.
- Risk 3 (Unencrypted Comm - Direct): **I (Information Disclosure)** — Transmitting sensitive authentication data over unencrypted HTTP allows attackers to sniff and read credentials in transit.
- Risk 4 (Unencrypted Comm - Proxy): **I (Information Disclosure)** — Internal traffic lacks encryption, meaning an attacker who breaches the network can intercept and read data flowing to the app.
- Risk 5 (Unnecessary Asset): **D (Denial of Service) / I (Information Disclosure)** — An unused but exposed persistent storage component expands the attack surface, making it an easy target for resource exhaustion or data leaks.

### Trust boundary observation
Looking at `data-flow-diagram.png`, name one arrow crossing a trust boundary that
appears in your top-5 risks. Why is that arrow particularly attractive to an attacker?

**Observation:** The arrow representing the communication link **"Direct to App (no proxy)"** crosses the trust boundary from the uncontrolled "Internet" directly to the internal application without encryption. 
**Why it's attractive:** This arrow carries highly sensitive authentication data (passwords, tokens). Because it crosses from a public network to the internal app without TLS/HTTPS encryption, an attacker doesn't even need to hack the server; they can simply sniff the network traffic (e.g., on public Wi-Fi) to steal credentials.





## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 4 | 0 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 6 | +1 |
| **Total** | 23 | 23 | 0 |

### Which rules are GONE in the secure variant?
List 3 rule IDs that fired in baseline but not in secure-variant:
1. `unencrypted-communication` (for Direct to App link) — fixed by changing `protocol: http` to `protocol: https`.
2. `unencrypted-asset` (for Persistent Storage) — fixed by adding `encryption: data-with-symmetric-shared-key`.
3. `sql-injection` (or related missing validation on DB link) — fixed by explicitly declaring "parameterized queries and prepared statements" in the connection description.

### Which rules are STILL THERE in the secure variant?
Threat modeling never reaches zero risk. List 2 rules that still fire and explain why
your changes didn't eliminate them (2-3 sentences each).

1. `cross-site-scripting` (XSS): Still fires because our changes were strictly infrastructure-level (HTTPS, DB encryption). We did not add any application-level input validation or Web Application Firewall (WAF) to prevent malicious scripts in user input.
2. `unencrypted-communication` (Reverse Proxy to App): Still fires because we only secured the external perimeter. The internal connection behind the reverse proxy remains plain HTTP, which is accurately flagged as an internal risk.

### Honesty check
Did the total drop more than 50%? If yes, what does that say about the cost-benefit
of these particular hardening changes vs. the work you'd need to fully eliminate the rest?

**Answer:** No, the total risk count did not drop by 50% (it remained at 23, with only minor severity shifts). This demonstrates a crucial reality in threat modeling: implementing "quick win" infrastructure hardening (TLS, at-rest encryption) is necessary but insufficient. It does not eliminate the vast majority of application-layer risks (like XSS, missing internal auth, or business logic flaws), which require deeper, more costly code-level remediation to fix.