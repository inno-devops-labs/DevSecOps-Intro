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
1. **unencrypted-communication** - <b>Unencrypted Communication</b> named <b>Direct to App (no proxy)</b> between <b>User Browser</b> and <b>Juice Shop Application</b> transferring authentication data (like credentials, token, session-id, etc.); severity elevated; affecting user-browser
2. **unencrypted-communication** - <b>Unencrypted Communication</b> named <b>To App</b> between <b>Reverse Proxy</b> and <b>Juice Shop Application</b>; severity elevated; affecting reverse-proxy
3. **cross-site-scripting** - <b>Cross-Site Scripting (XSS)</b> risk at <b>Juice Shop Application</b>; severity elevated; affecting juice-shop
4. **missing-authentication** - <b>Missing Authentication</b> covering communication link <b>To App</b> from <b>Reverse Proxy</b> to <b>Juice Shop Application</b>; severity elevated; affecting juice-shop
5. **unnecessary-technical-asset** - <b>Unnecessary Technical Asset</b> named <b>Persistent Storage</b>; severity low; affecting persistent-storage

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
### STRIDE mapping (Lecture 2 slide 7)
- Risk 1 (`unencrypted-communication`, Browser → App): **I** (Information Disclosure), secondary **T** (Tampering) — credentials and session tokens travel in cleartext, so anyone on the network path can read them and could also alter the traffic in transit.
- Risk 2 (`unencrypted-communication`, Reverse Proxy → App): **I** (Information Disclosure), secondary **T** (Tampering) — the internal proxy-to-app channel is unencrypted, exposing the same data in transit to anyone who can observe or modify the internal link.
- Risk 3 (`cross-site-scripting`): **T** (Tampering), leading to **I** and **E** — injected script alters the page rendered in the victim's browser and can steal session tokens or act on the user's behalf.
- Risk 4 (`missing-authentication`): **S** (Spoofing), secondary **E** (Elevation of Privilege) — with no authentication on the link, an attacker can impersonate a legitimate caller and reach functionality meant for authenticated parties.
- Risk 5 (`unnecessary-technical-asset`, Persistent Storage): **I** (Information Disclosure) — an unused storage asset left in the design keeps an extra, unguarded place where sensitive data could reside and leak; primarily an attack-surface-reduction finding rather than one classic STRIDE threat.

### Trust boundary observation
The arrow **User Browser → Juice Shop Application** (`http`, "Direct to App (no proxy)") crosses from the untrusted **Internet** zone straight into the innermost **Container Network**, bypassing the Reverse Proxy. It maps to Risk 1 (`unencrypted-communication`).

It's attractive to an attacker because it carries credentials in cleartext HTTP across the Internet boundary with no TLS and no proxy in between — anyone on the path can sniff the credentials or run a man-in-the-middle attack to reach the app's trust zone directly.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High     | 0 | 0 | 0 |
| Elevated | 4 | 1 | −3 |
| Medium   | 14 | 12 | −2 |
| Low      | 5 | 5 | 0 |
| **Total** | **23** | **18** | **−5** |

### Rules GONE in secure variant
1. `unencrypted-communication` — fixed by `protocol: https` on both the Browser→App and Proxy→App links.
2. `unencrypted-asset` — fixed by at-rest encryption on Persistent Storage and the Juice Shop app.
3. `missing-authentication` — fixed by adding `authentication` + `authorization` on the Proxy→App link.

### Rules STILL firing
1. `cross-site-scripting` — app-level flaw; transport/storage encryption doesn't affect input handling, so it stays.
2. `unnecessary-technical-asset` — Persistent Storage still has no communication links; encryption doesn't connect it to the data flow.

### Honesty check
No — total dropped 23 → 18 (~22%), not over 50%. Four cheap config edits cleared the easy transport/storage risks, but the rest are app-level (XSS, CSRF, SSRF) and architectural (missing WAF, vault, hardening) and need real engineering, not YAML edits. Classic threat-modeling curve: first mitigations are cheap and high-impact, the rest aren't.
