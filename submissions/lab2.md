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
1. **missing-authentication** — <b>Cross-Site Scripting (XSS)</b> risk at <b>Juice Shop Application</b>; severity <b>elevated</b>; affecting <b>juice-shop</b>
2. **unencrypted-communication** — <b>Unencrypted Communication</b> named <b>Direct to App (no proxy)</b> between <b>User Browser</b> and <b>Juice Shop Application</b> transferring authentication data (like credentials, token, session-id, etc.); severity <b>elevated</b>; affecting <b>juice-shop</b>
3. **unencrypted-communication** — <b>Unencrypted Communication</b> named <b>To App</b> between <b>Reverse Proxy</b> and <b>Juice Shop Application</b>; severity <b>elevated</b>; affecting <b>reverse-proxy</b>
4. **cross-site-scripting** — <b>Cross-Site Scripting (XSS)</b> risk at <b>Juice Shop Application</b>; severity <b>elevated</b>; affecting <b>juice-shop</b>
5. **unnecessary-data-transfer** — <b>Unnecessary Data Transfer</b> of <b>Tokens & Sessions</b> data at <b>User Browser</b> from/to <b>Juice Shop Application</b>; severity <b>low</b>; affecting <b>user-browser</b>

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **S** — An attacker can spoof the request source by posing as a trusted person.
- Risk 2: **I** — Internal traffic between the proxy and the application is not encrypted, which leads to data leakage if the internal network is compromised.
- Risk 3: **I** — The lack of authentication between Reverse Proxy and the application allows an attacker to forge a request and impersonate a trusted party.
- Risk 4: **T/I** — An attacker can inject malicious Javascript.
- Risk 5: **I** — such data transfer may reveal non-public information. 

### Trust boundary observation
An arrow from **User Browser** to **Juice Shop Application**  crosses a trust boundary. This data transfer uses HTTP, which means that all data, including login credentials, JWT tokens, and session IDs, is transferred in clear text. This is especially dangerous because the arrow carries authentication data.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | 3 |
| Medium | 14 | 13 | 1 |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 19 | 4 |

### Which rules are GONE in the secure variant?
List 3 rule IDs that fired in baseline but not in secure-variant:
1. `missing-authentication` — fixed by `authentication: client-certificate` to the `To App` communication link between Reverse Proxy and Juice Shop Application
2. `unencrypted-communication` — fixed by changing `protocol: http` to `https`
3. `unencrypted-asset` — (Not gone, but decreased from 2 to 1), fixed by adding `encryption: data-with-symmetric-shared-key` to Persistent Storage

### Which rules are STILL THERE in the secure variant?
- **cross-site-scripting** — We added HTTPS and database encryption, but this has no impact on user input. An attacker could still inject a malicious script into the search bar, for example. To resolve this issue, we needed to sanitize all user input before displaying it on the page.
- **unnecessary-data-transfer** — The application transmits personal data that is not required for its operation. The server continues to send these same fields in the JSON file. To resolve this issue, we could rewrite the API endpoints to return only the necessary fields.

### Honesty check

The total risk count dropped from 23 to 19, which is less than 50% of total drop. The most significant changes occurred in the risk category `elevated`. Fixing network-level errors is a quick and easy process, but it does not significantly reduce the overall risk profile; consequently, we would still need to address the remaining code-level issues, which take longer to resolve.