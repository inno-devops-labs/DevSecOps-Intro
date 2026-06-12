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
1. **unencrypted-communication** — Unencrypted Communication "Direct to App (no proxy)" between User Browser and Juice Shop Application, transferring authentication data (credentials, token, session-id); severity Elevated; affecting `user-browser`
2. **unencrypted-communication** — Unencrypted Communication "To App" between Reverse Proxy and Juice Shop Application; severity Elevated; affecting `reverse-proxy`
3. **missing-authentication** — Missing Authentication covering the communication link "To App" from Reverse Proxy to Juice Shop Application; severity Elevated; affecting `juice-shop`
4. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity Elevated; affecting `juice-shop`
5. **missing-waf** — Missing Web Application Firewall (WAF) risk at Juice Shop Application; severity Low; affecting `juice-shop`

### STRIDE mapping (Lecture 2 slide 7)
- Risk 1: **Information Disclosure (I)** — Sensitive auth data (credentials, session tokens) travels in plaintext over the wire, allowing any network observer to read it.
- Risk 2: **Information Disclosure (I)** — Same issue on the proxy-to-app hop; even an internal segment carrying auth data unencrypted is a disclosure risk if that segment is compromised.
- Risk 3: **Spoofing (S)** — Without authentication on the proxy-to-app link, the application cannot verify that requests genuinely originated from the trusted reverse proxy, allowing a spoofed source to reach it directly.
- Risk 4: **Tampering (T)** — XSS lets an attacker inject and execute script in another user's browser context, tampering with the page content and potentially their session.
- Risk 5: **Tampering / Information Disclosure (T/I)** — A missing WAF removes a layer that would normally filter malicious payloads (SQLi, XSS) before they reach the app, increasing both tampering and disclosure risk.

### Trust boundary observation
Looking at `data-flow-diagram.png`, the arrow from **User Browser → Reverse Proxy → Juice Shop Application** crosses from the "Internet" trust boundary into the "Server/Container" trust boundary. This arrow appears in risks #1–#3 above. It's particularly attractive to an attacker because it's the single entry point where untrusted external traffic (carrying login credentials and session tokens) first meets the application's internal network — compromising or eavesdropping on this hop gives an attacker both credential theft (risk 1) and a path to impersonate the proxy itself (risk 3).

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
1. `unencrypted-asset` — Persistent Storage was flagged as an unencrypted technical asset; fixed by setting `encryption: data-with-symmetric-shared-key`.
2. `unencrypted-communication` — "Direct to App (no proxy)" link from User Browser to Juice Shop Application; fixed by changing `protocol: http` → `protocol: https`.
3. `unencrypted-communication` — "To App" link from Reverse Proxy to Juice Shop Application; fixed by changing `protocol: http` → `protocol: https`.

### Which rules are STILL THERE in the secure variant?
1. **missing-authentication** — Still fires on the Reverse Proxy → Juice Shop Application link. Switching the transport to HTTPS encrypts the channel but does nothing to verify *who* is sending the request; the app still has no mechanism to confirm the request genuinely came from the trusted proxy rather than any other host on the network. Fixing this would require adding mutual TLS or a shared-secret header check, which is an architectural/code change, not a YAML field.
2. **missing-waf** — Still fires on Juice Shop Application. A WAF is an entirely separate infrastructure component that needs to be deployed and configured; none of our 4 field-level edits (protocols, encryption) introduce or imply a WAF. This risk can only be closed by adding a new technical asset (the WAF itself) to the model and routing traffic through it.

### Honesty check
The total dropped from 23 to 20 — about 13%, far from 50%. This shows that "easy" hardening (flipping `http` to `https` and turning

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 6 |
| Medium | 16 |
| Low | 5 |
| **Total** | 28 |

### Three auth-specific risks (NOT in the baseline model's top 5)

1. **sql-nosql-injection** — STRIDE: **Tampering (T)** — Mitigation: The Auth API queries the User Credential Store via "Verify Credentials" using raw query construction. Mitigation is to use parameterized queries / prepared statements (and an ORM with built-in escaping) for every credential lookup, so user-supplied login input can never alter the query structure.

2. **missing-identity-store** — STRIDE: **Spoofing (S)** — Mitigation: The model has no dedicated identity provider; the Auth API itself both authenticates users and issues tokens. Introducing a separate identity store/IdP (or at minimum a hardened, single-purpose auth service) reduces the blast radius if the main application is compromised, since the credential-verification logic is isolated from the rest of the app's attack surface.

3. **missing-authentication-second-factor** — STRIDE: **Spoofing (S) / Elevation of Privilege (E)** — Mitigation: Login, authenticated API requests, and admin-endpoint requests all lack a second factor. Adding TOTP-based or WebAuthn MFA — especially enforced for the Admin Endpoint — means a stolen password or leaked JWT alone is not sufficient for an attacker to authenticate as that user or reach admin functionality.

### Reflection
Building the focused auth model surfaced risks the baseline architecture model never flagged at all — most notably the **SQL/NoSQL injection** finding (High severity, the highest of any risk across both models) and the **missing identity store / missing second factor** findings. The baseline model treats Juice Shop as a single opaque "process" asset, so it has no visibility into how that process talks to its credential database or issues tokens internally. By decomposing just the auth flow into its constituent parts (Auth API, Token Signer, Credential Store, Admin Endpoint), Threagile could reason about the specific communication link between the Auth API and the credential database and flag injection risk on it — a finding that simply doesn't exist at the architecture level. This confirms the lecture's point: feature-level threat models catch *implementation-adjacent* risks (injection, missing MFA on a specific flow, missing identity provider) that architecture-level models, by design, abstract away.