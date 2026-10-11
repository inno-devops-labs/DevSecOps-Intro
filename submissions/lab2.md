## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|------:|
| Critical |     0 |
| High |     0 |
| Elevated |     4 |
| Medium |    14 |
| Low |     5 |
| **Total** |    23 |

### Top 5 risks (paste from `jq` output)
1. **missing-authentication@reverse-proxy>to-app@reverse-proxy@juice-shop** — <b>Missing Authentication</b> covering communication link <b>To App</b> from <b>Reverse Proxy</b> to <b>Juice Shop App</b>; severity elevated; affecting juice-shop
2. **cross-site-scripting@juice-shop** — <b>Cross-Site Scripting (XSS)</b> risk at <b>Juice Shop App</b>; severity elevated; affecting juice-shop
3. **unencrypted-communication@user-browser>direct-app@user-browser@juice-shop** — <b>Unencrypted Communication</b> named <b>Direct App</b> between <b>User Browser</b> and <b>Juice Shop App</b> transferring authentication data (like credentials, token, session-id, etc.); severity elevated; affecting user-browser
4. **unencrypted-communication@reverse-proxy>to-app@reverse-proxy@juice-shop** — <b>Unencrypted Communication</b> named <b>To App</b> between <b>Reverse Proxy</b> and <b>Juice Shop App</b>; severity elevated; affecting reverse-proxy
5. **unnecessary-data-transfer@tokens-sessions@user-browser@juice-shop** — <b>Unnecessary Data Transfer</b> of <b>Tokens & Sessions</b> data at <b>User Browser</b> from/to <b>Juice Shop App</b>; severity low; affecting user-browser

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **S** — without authentication on the communication link, an unauthorized party could impersonate a trusted component and access the application.
- Risk 2: **T/I** — XSS allows injected scripts to modify application behavior and potentially steal user data such as cookies or session information.
- Risk 3: **I** — transmitting authentication data without encryption exposes credentials, tokens, or sessions to interception.
- Risk 4: **T/I** — traffic between internal components could be intercepted or altered if encryption is absent.
- Risk 5: **I** — transferring more sensitive session data than necessary increases exposure and leakage risk.

### Trust boundary observation
Looking at `data-flow-diagram.png`, name one arrow crossing a trust boundary that
appears in your top-5 risks. Why is that arrow particularly attractive to an attacker?
`Answer: Reverse Proxy -> Juice Shop App. This arrow is particularly attractive to an attacker because it crosses a trust boundary and carries internal application traffic over HTTP, creating opportunities to intercept, manipulate, or bypass protections before requests reach the Juice Shop application.`


## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical |        0 |      0 | 0 |
| High |        0 |      0 | 0 |
| Elevated |        4 |      6 | 2 |
| Medium |       14 |     13 | 1 |
| Low |        5 |      4 | 1 |
| **Total** |       23 |     23 | 0 |

### Which rules are GONE in the secure variant?
List 3 rule IDs that fired in baseline but not in secure-variant:
1. `unencrypted-communication@user-browser>direct-app` — fixed by protocol: http -> https
2. `unencrypted-asset@persistent-storage` — fixed by encryption: none -> data-with-symmetric-shared-key

### Which rules are STILL THERE in the secure variant?
Threat modeling never reaches zero risk. List 2 rules that still fire and explain why
your changes didn't eliminate them (2-3 sentences each).
`Answer: unencrypted-communication@reverse-proxy>to-app — proxy->app link is still protocol: http; never touched it.
missing-authentication@reverse-proxy>to-app — authentication: none was never changed; adding the Storage link with the same field likely added new instances, explaining Elevated +2.`

### Honesty check
Did the total drop more than 50%? If yes, what does that say about the cost-benefit
of these particular hardening changes vs. the work you'd need to fully eliminate the rest?
```
Drop >50%? No — 23 -> 23, zero drop.
Why? Adding the To Storage link modeled reality more accurately but introduced new findings that cancelled the gains.
Cost-benefit? The two fixes that worked were cheap YAML edits; the survivors need real runtime changes (internal TLS, proxy credentials) — that's where the actual work is.
```