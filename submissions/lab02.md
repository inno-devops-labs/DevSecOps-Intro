## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|------:|
| Critical | <0> |
| High | <0> |
| Elevated | <4> |
| Medium | <14> |
| Low | <5> |
| **Total** | <23> |

### Top 5 risks (paste from `jq` output)
1. **<issing-authentication>** — <Missing Authentication covering communication link "To App" from Reverse Proxy to Juice Shop Application>; severity <elevated>; affecting <juice-shop>
2. **<cross-site-scripting>** — <Cross-Site Scripting (XSS) risk at Juice Shop Application; severity elevated>; severity <elevated>; affecting <juice-shop>
3. **<unencrypted-communication>** — <Unencrypted Communication named "To App" between Reverse Proxy and Juice Shop Application>; severity <elevated>; affecting <reverse-proxy>
4. **<unencrypted-communication>** — <nencrypted Communication named "Direct to App (no proxy)" between User Browser and Juice Shop Application transferring authentication data (credentials, token, session-id, etc.)>; severity <elevated>; affecting <user-browser>
5. **<missing-build-infrastructure>** — <Missing Build Infrastructure in the threat model (referencing asset Juice Shop Application as an example)>; severity <medium>; affecting <juice-shop>

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **<S>** — <with no authentication on the link, anyone can call the app pretending to be the proxy.>
- Risk 2: **T** — XSS injects attacker JavaScript that alters what runs in the victim's browser (also leaks data, so partly I).
- Risk 3: **I** — proxy→app traffic in clear text can be sniffed on the host network.
- Risk 4: **I** — credentials and session tokens travel in clear text and can be captured, then replayed (which becomes Spoofing).
- Risk 5: **T** — without a hardened build pipeline, build artifacts can be tampered with before deployment.

### Trust boundary observation
Looking at `data-flow-diagram.png`, name one arrow crossing a trust boundary that
appears in your top-5 risks. Why is that arrow particularly attractive to an attacker?
Arrow "Direct to App (no proxy)" from User Browser to Juice Shop Application goes from the Internet boundary into the Container Network boundary, and is labeled `http` (no TLS). It is attractive to an attacker because login credentials and session tokens travel over an untrusted network in clear text — anyone able to observe the traffic can capture and reuse them.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | <0> | <0> | <0-0=0> |
| High | <0> | <0> | <0-0=0> |
| Elevated | <4> | <2> | <2-4=-2> |
| Medium | <14> | <13> | <13-14=-1> |
| Low | <5> | <5> | <5-5=0> |
| **Total** | <23> | <20> | <20-23=-3> |

### Which rules are GONE in the secure variant?
List 3 rule IDs that fired in baseline but not in secure-variant:
1. `<unencrypted-communication>` — fixed by `<changing the link `protocol` from `http` to `https`>` (Reverse Proxy → Juice Shop App, "To App")
2. `<unencrypted-communication>` — fixed by `<changing the link `protocol` from `http` to `https`>`(User Browser → Juice Shop App, "Direct to App")
3. `<unencrypted-asset>` — fixed by `<setting the technical asset's `encryption` from `none` to `data-with-symmetric-shared-key`>`

### Which rules are STILL THERE in the secure variant?
Threat modeling never reaches zero risk. List 2 rules that still fire and explain why
your changes didn't eliminate them (2-3 sentences each).
1. `missing-authentication` — Encrypting the channel (TLS) does not add identity checks. The communication links still have `authentication: none`, so any caller can talk to the app pretending to be the proxy. TLS protects data in transit but not who the caller is.
2. `cross-site-scripting` — XSS is a code-level flaw in how the app handles user input. No YAML field can remove it; it would require input validation and output encoding in the application code, which is outside what the threat model can express.



### Honesty check
Did the total drop more than 50%? If yes, what does that say about the cost-benefit
of these particular hardening changes vs. the work you'd need to fully eliminate the rest?
No — the total dropped from 23 to 20 (about 13%). One-line hardening of transport (TLS) and storage (encryption-at-rest) gives a few high-value wins, but most remaining findings — missing-authentication, missing-waf, missing-vault, missing-identity-store, XSS, CSRF, SSRF, hardening, build-infrastructure — are architectural and code-level problems that need real engineering work (adding components, changing code, designing identity propagation). Cheap field toggles in the YAML cannot replace that work.

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | <0> |
| High | <1> |
| Elevated | <8> |
| Medium | <19> |
| Low | <5> |
| **Total** | 33> |

### Three auth-specific risks (NOT in the baseline model's top 5)
For each, name:
- The rule ID Threagile fires
- The STRIDE letter
- A 1-2 sentence mitigation in plain English

1. **<sql-nosql-injection>** — STRIDE: <T> — Mitigation: <ban string concatenation in queries to the credential store; use parameterized queries everywhere and validate input shape on the auth endpoint>
2. **<missing-identity-propagation>** — STRIDE: <E> — Mitigation: <propagate the end-user identity from the auth API down to Token Service and Admin Endpoint, and re-check authorization at each layer (defense-in-depth) instead of trusting the perimeter alone>
3. **<unguarded-access-from-internet>** — STRIDE: <S> — Mitigation: <put a WAF/rate-limit in front of the auth endpoint and close direct internet exposure of internal services so credential stuffing and forged requests are harder>

### Reflection (2-3 sentences)
What did building the focused model surface that the baseline architecture model missed?
(Hint: feature-level threat models often find what architecture-level ones can't.)
The focused auth-only model surfaced flow-specific risks that the broad architecture model missed: injection on the credential store, lack of identity propagation between internal services, and direct internet exposure of the auth endpoint. When the model is small and scoped to one feature, the tool actually exercises that path instead of drowning the same checks in noise from unrelated components.