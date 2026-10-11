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
1. **cross-site-scripting** -  "<b>Cross-Site Scripting (XSS)</b> risk at <b>Juice Shop Application</b>"; severity "elevated"; affecting "juice-shop"
2. **unencrypted-communication** - "<b>Unencrypted Communication</b> named <b>Direct to App (no proxy)</b> between <b>User Browser</b> and <b>Juice Shop Application</b> transferring authentication data (like credentials, token, session-id, etc.)"; severity "elevated"; affecting "user-browser"
3. **unencrypted-communication** - "<b>Unencrypted Communication</b> named <b>To App</b> between <b>Reverse Proxy</b> and <b>Juice Shop Application</b>"; severity "elevated"; affecting "reverse-proxy"
4. **missing-authentication** - "<b>Missing Authentication</b> covering communication link <b>To App</b> from <b>Reverse Proxy</b> to <b>Juice Shop Application</b>"; severity "elevated"; affecting "juice-shop"
5. **unnecessary-data-transfer** - "<b>Unnecessary Data Transfer</b> of <b>Tokens & Sessions</b> data at <b>User Browser</b> from/to <b>Juice Shop Application</b>"; severity "low"; affecting "user-browser"

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **T** — Possible injections
- Risk 2: **I** - Passwords and tokens interception possible
- Risk 3: **I** - Internal traffic interception possible
- Risk 4: **S** - Authentication; attacker logs in as another user
- Risk 5: **D** - Increased load on the system

### Trust boundary observation
The User Browser -> Juice Shop Application arrow crosses a trust boundary and represents the 2nd risk from the Top 5 because it ignores the proxy. All data is passed unencrypted through that connection, which means that anyone could steal the data.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 2 | 2 |
| Medium | 14 | 13 | 1 |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 20 | 3 |

### Which rules are GONE in the secure variant?
List 3 rule IDs that fired in baseline but not in secure-variant:
1. `unencrypted-communication` — fixed by `force https into the app`
This is the only rule that is gone. The 2 and 3 risks from the Top 5.

### Which rules are STILL THERE in the secure variant?
Threat modeling never reaches zero risk. List 2 rules that still fire and explain why
your changes didn't eliminate them (2-3 sentences each).
All the other rules are still there. I believe it's because Juice Shop is deliberately vulnerable and some things are beyond our ability to fix. Moreover, the changes we made had nothing to do with authentication 

### Honesty check
Did the total drop more than 50%? If yes, what does that say about the cost-benefit
of these particular hardening changes vs. the work you'd need to fully eliminate the rest?
No, 3 risks out of 23 is definitely less than 50%, and I have no idea why that happened.