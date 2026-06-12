# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|------:|
| Critical |     0 |
| High     |     0 |
| Elevated |     4 |
| Medium   |    14 |
| Low      |     5 |
| **Total**|  **23** |

### Top 5 risks (from `risks.json`)
1. **missing-authentication** — Missing Authentication covering link To App from Reverse Proxy to Juice Shop Application; severity Elevated; affecting juice-shop
2. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity Elevated; affecting juice-shop
3. **unencrypted-communication** — Unencrypted Communication on Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data; severity Elevated; affecting user-browser
4. **unencrypted-communication** — Unencrypted Communication on To App between Reverse Proxy and Juice Shop Application; severity Elevated; affecting reverse-proxy
5. **unnecessary-technical-asset** — Unnecessary Technical Asset named Persistent Storage; severity Low; affecting persistent-storage

### STRIDE mapping
- Risk 1 (missing-authentication): **S** (Spoofing) — without authentication on the internal proxy→app link, any process on the host network can forge requests to the app as if it were the legitimate proxy.
- Risk 2 (cross-site-scripting): **T** (Tampering) — malicious scripts injected via product reviews or other inputs tamper with the DOM in victim browsers, enabling session hijack or data exfiltration.
- Risk 3 (unencrypted-communication, Direct to App): **I** (Information Disclosure) — plaintext HTTP on port 3000 exposes session tokens and credentials to any network-level observer or ARP-spoofing attacker.
- Risk 4 (unencrypted-communication, To App): **I** (Information Disclosure) — even after TLS termination at the proxy, the internal HTTP hop from proxy to app leaks tokens in plaintext within the host network.
- Risk 5 (unnecessary-technical-asset): **D** (Denial of Service) — an unused but mounted persistent storage volume increases the attack surface; if the volume is filled or corrupted it can deny service to the application.

### Trust boundary observation
In `data-flow-diagram.png`, the arrow **User Browser → Juice Shop Application** (Direct to App, HTTP on port 3000) crosses the Internet→Host trust boundary without TLS. This arrow is particularly attractive to an attacker because it carries session tokens and credentials in plaintext, meaning a passive network tap or an ARP-spoofing attack is sufficient to harvest valid sessions with zero interaction with the application logic itself.


## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure |  Δ |
|----------|---------:|-------:|---:|
| Critical |        0 |      0 |  0 |
| High     |        0 |      0 |  0 |
| Elevated |        4 |      2 | -2 |
| Medium   |       14 |     13 | -1 |
| Low      |        5 |      5 |  0 |
| **Total**|   **23** | **20** | **-3** |

### Which rules are GONE in the secure variant?
1. `unencrypted-communication` (elevated) — fixed by `protocol: https` on the **Direct to App** link (User Browser → Juice Shop)
2. `unencrypted-communication` (elevated) — fixed by `protocol: https` on the **To App** link (Reverse Proxy → Juice Shop)
3. `unencrypted-asset` (medium, one instance) — fixed by `encryption: data-with-symmetric-shared-key` on Persistent Storage

### Which rules are STILL THERE in the secure variant?
1. **missing-authentication** (elevated) — the internal link from Reverse Proxy to Juice Shop still carries no authentication token. Setting `protocol: https` encrypts the channel but does not prove the caller's identity; eliminating this risk would require mTLS or a shared secret header between proxy and app.
2. **server-side-request-forgery** (medium) — the Juice Shop application can still initiate outbound HTTP requests based on user-supplied input (e.g. profile image URL fetch or WebHook callback). Setting `ip_filtered: true` on the WebHook link signals intent but Threagile still fires the rule because the app logic itself is not constrained; a server-side allowlist of permitted outbound destinations is required to close it.

### Honesty check
Yes, the total dropped by 3 (≈13%), not over 50%. The changes fixed only the most obvious transport-layer issues — flipping a protocol field or adding an encryption flag costs minutes of work. The remaining 20 risks require architectural changes (mTLS between components, a secrets vault, WAF, 2FA, hardened base images) or application-level fixes (input sanitisation for XSS/CSRF, SSRF allowlists). This illustrates a classic cost-benefit asymmetry: perimeter hardening is cheap and fast but eliminates only a small fraction of the total risk surface; the expensive application-level work is where most risk actually lives.

