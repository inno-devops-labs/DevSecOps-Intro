# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

## Task 1

Severity table (from `labs/lab2/output/risks.json`):

| Severity | Count |
|---|---|
| elevated | 4 |
| medium | 14 |
| low | 5 |
| **Total** | **23** |

Top five risks, ranked critical → high → elevated → medium → low:

| Severity | Rule ID | Asset |
|---|---|---|
| elevated | unencrypted-communication | user-browser |
| elevated | unencrypted-communication | reverse-proxy |
| elevated | missing-authentication | juice-shop |
| elevated | cross-site-scripting | juice-shop |
| medium | container-baseimage-backdooring | juice-shop |

STRIDE mapping for each:

1. **unencrypted-communication** (`Direct to App (no proxy)`, User Browser → Juice Shop Application) — **Information Disclosure**. The link carries credentials, tokens and session IDs in clear HTTP; anyone on the network path can read that traffic.
2. **unencrypted-communication** (`To App`, Reverse Proxy → Juice Shop Application) — **Information Disclosure**. Even though the proxy terminates TLS from the browser, the internal hop from proxy to app is plain HTTP, so the same session data is exposed again on that segment.
3. **missing-authentication** (`To App`, Reverse Proxy → Juice Shop Application) — **Spoofing**. Because the app does not authenticate its caller on this link, anything that can reach the app's internal port can impersonate the trusted reverse proxy.
4. **cross-site-scripting** (Juice Shop Application) — **Tampering**. A successful XSS injects attacker-controlled script that modifies the page's DOM and behavior as seen by other users' browsers.
5. **container-baseimage-backdooring** (Juice Shop Application) — **Tampering**. A compromised or backdoored base image tampers with the software supply chain before the container ever runs, independent of anything the application code does.

**Trust-boundary crossing in the top five:** the `Direct to App (no proxy)` arrow (User Browser → Juice Shop Application) crosses straight from the **Internet** trust boundary into the **Container Network** boundary, skipping the intermediate **Host** boundary entirely — in the data-flow diagram this is the arrow that bypasses the Reverse Proxy node altogether. It is worth an attacker's time precisely because it is the shortest path to the actual application logic: it skips the proxy's TLS termination and security-header injection, landing the attacker directly on the unauthenticated, unencrypted app port that the "legitimate" path through the proxy was meant to shield.

## Task 2

Baseline vs. secure severity comparison:

| Severity | Baseline | Secure | Delta |
|---|---|---|---|
| elevated | 4 | 1 | -3 |
| medium | 14 | 12 | -2 |
| low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **-5** |

Rule IDs that disappeared (`gone:`), each tied to the field that removed it:

- **unencrypted-communication** — removed by changing `protocol: http` → `protocol: https` on both the `Direct to App (no proxy)` link (User Browser → Juice Shop) and the `To App` link (Reverse Proxy → Juice Shop).
- **missing-authentication** — removed by changing `authentication: none` → `authentication: client-certificate` (and `authorization: none` → `authorization: technical-user`) on the `To App` link from Reverse Proxy to Juice Shop.
- **unencrypted-asset** — removed by changing `encryption: none` → `encryption: data-with-symmetric-shared-key` on both the Juice Shop Application and Persistent Storage technical assets.

No new rule categories appeared (`new:` was empty).

Two rules that still fire, and why the edits could not remove them:

- **cross-site-scripting** still fires on the Juice Shop Application. XSS is a property of how the application renders untrusted input in its own code — no combination of transport encryption, link authentication, or at-rest encryption in the YAML model touches how the app escapes (or fails to escape) user-supplied HTML, so this risk is untouched by any of the three hardening edits.
- **missing-waf** still fires. It exists because the model has no Web Application Firewall asset in front of the Juice Shop Application at all — closing it requires adding a new protective component to the architecture, not changing a field on an asset or link that already exists.

The total dropped by roughly a fifth (23 → 18), not to zero, because the three edits only closed *transport and asset-configuration* gaps — cleartext protocols, an unauthenticated internal link, and unencrypted-at-rest storage. What is left is almost entirely *application-code and missing-component* risk: XSS, SQL/NoSQL-style injection surface, SSRF via the webhook, and the complete absence of a WAF, vault, identity store, and hardened build pipeline. Closing the remainder would require adding real infrastructure (a WAF, a secrets vault) and, more importantly, fixing code — output encoding, input validation, hardened base images from a trusted registry with provenance checks. **Cross-site-scripting is the clearest example of a risk no YAML edit can close**: it can only be fixed by changing how the Juice Shop application code handles and renders user input, which is outside anything a threat-model file can express or remediate.

## Bonus

Severity table for `threagile-model-auth.yaml`:

| Severity | Count |
|---|---|
| high | 2 |
| elevated | 3 |
| medium | 20 |
| low | 6 |
| **Total** | **31** |

Three risks this feature-level model surfaced that the baseline architecture model did not:

1. **`sql-nosql-injection`** (High) — at the Login Endpoint and Admin Endpoint, both querying the Credential Store. STRIDE: **Tampering** (attacker-controlled input alters the query executed against the datastore, potentially reading or writing unintended data). Mitigation: use parameterized queries or an ORM with prepared statements for every Credential Store access, never string-built SQL/NoSQL queries.
2. **`missing-identity-propagation`** (Medium) — on the `Request Token Issuance` link from Login Endpoint to Token Service. STRIDE: **Repudiation** (the Token Service mints a token without the original end-user's identity being propagated to it, so it cannot later prove, nor can an audit trail show, which authenticated user actually triggered a given token issuance). Mitigation: forward a signed assertion of the verified end-user identity on this internal call instead of only a service-to-service credential.
3. **`unguarded-access-from-internet`** (Medium) — on both the Login Endpoint and Token Verification, reachable directly from the User Browser with nothing in front of them. STRIDE: **Denial of Service** (with no gateway or rate limiter shielding these internet-facing entry points, they can be flooded or brute-forced directly). Mitigation: put an API gateway or WAF with rate limiting in front of both internet-facing endpoints.

What a feature-level model showed that the architecture-level one could not: the architecture model treated the entire Juice Shop server as one opaque node, so it had no way to reason about the internal call from a login handler to a token-signing component or about how credentials actually reach a database — that is exactly where the SQL/NoSQL injection and missing-identity-propagation risks live. It also let the admin authorization check become a concrete, inspectable line in the YAML (the `Forward to Admin (role-checked)` link's description and fields) instead of an assumption that "the app handles authorization somewhere," which is all the coarse architecture model could say.
