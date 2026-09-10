# Lab 2 — Submission

## Task 1

### Severity table (baseline)

| Severity | Count |
|----------|-------|
| critical | 0 |
| high     | 0 |
| elevated | 4 |
| medium   | 14 |
| low      | 5 |
| **Total** | **23** |

### Top 5 risks (ranked by severity)

| Severity | Rule ID | Most relevant asset |
|----------|---------|---------------------|
| elevated | missing-authentication | juice-shop |
| elevated | unencrypted-communication | user-browser |
| elevated | unencrypted-communication | reverse-proxy |
| elevated | cross-site-scripting | juice-shop |
| medium   | missing-identity-store | reverse-proxy |

### STRIDE mapping and reasoning

**1. missing-authentication — S (Spoofing)**
The link from the reverse proxy to Juice Shop carries no authentication. An attacker who can reach the internal network could impersonate the proxy and send arbitrary requests directly to the app as if they came from a trusted source.

**2. unencrypted-communication (user-browser) — I (Information Disclosure)**
The "Direct to App" link uses plain HTTP. Any session token or credential sent over that link is readable in transit by anyone on the same network — dorm Wi-Fi, shared office network, or a local ARP spoof.

**3. unencrypted-communication (reverse-proxy) — I (Information Disclosure)**
The internal hop from the proxy to the app also uses HTTP. Even if the front-facing connection is TLS-terminated by the proxy, tokens forwarded internally are still exposed on the host network between the two processes.

**4. cross-site-scripting — T (Tampering)**
Juice Shop stores product descriptions containing raw HTML without sanitisation. A malicious script injected into a description gets executed in every user's browser that loads the product page, allowing tampering with the rendered page and theft of session tokens from localStorage.

**5. missing-identity-store — R (Repudiation)**
The model has no explicit identity store asset, so Threagile cannot verify that user identity is tracked and auditable. Without a provable identity trail, a user can deny having performed an action and there is no log record linked to a verified identity to refute that.

### Trust-boundary crossing worth an attacker's time

The **"Direct to App (no proxy)"** link from User Browser crosses the **Internet → Container Network** boundary (going through Host in the middle), carrying session tokens over plain HTTP. This arrow matters because it reaches the application layer directly without TLS termination — any network-adjacent attacker (same LAN, malicious router, ARP poisoning) can read the session token and replay it to authenticate as the victim without needing credentials. The fact that this link is optional ("no proxy" path) makes it easy to forget it is there.

---

## Task 2

### Hardening changes applied to `threagile-model-secure.yaml`

1. `Direct to App (no proxy)` link: `protocol: http` → `protocol: https`
2. `To App` link (Reverse Proxy → Juice Shop): `protocol: http` → `protocol: https`, `authentication: none` → `authentication: token`, `authorization: none` → `authorization: technical-user`
3. `Juice Shop Application` asset: `encryption: none` → `encryption: data-with-symmetric-shared-key`
4. `Persistent Storage` asset: `encryption: none` → `encryption: data-with-symmetric-shared-key`

### Severity comparison: baseline vs secure

| Severity | Baseline | Secure | Delta |
|----------|----------|--------|-------|
| critical | 0 | 0 | 0 |
| high     | 0 | 0 | 0 |
| elevated | 4 | 1 | -3 |
| medium   | 14 | 12 | -2 |
| low      | 5 | 5 | 0 |
| **Total** | **23** | **18** | **-5** |

### Rules removed (gone)

| Rule ID | Field change that removed it |
|---------|------------------------------|
| `missing-authentication` | `To App` link: `authentication: none` → `authentication: token` |
| `unencrypted-communication` | Both links to Juice Shop: `protocol: http` → `protocol: https` |
| `unencrypted-asset` | App and storage assets: `encryption: none` → `encryption: data-with-symmetric-shared-key` |

### Two rules that still fire

**cross-site-scripting** — XSS is an application-code vulnerability, not an architectural one. No amount of YAML edits to the threat model changes the fact that Juice Shop renders product descriptions without sanitisation. Fixing it requires code changes in the application itself.

**cross-site-request-forgery** — CSRF protection depends on how the app handles state-changing requests (checking the `Origin` header, using CSRF tokens, etc.). The model can declare that a link is readonly or require stronger authentication, but the underlying application still needs to implement CSRF mitigations. A YAML change doesn't add them.

### What risk is left, and why it can't go to zero

The remaining risks are mostly application-level and operational: XSS, CSRF, missing WAF, missing hardening, missing vault, container base image backdooring. These are not properties of the network topology or the protocol choices — they reflect the fact that the application code is deliberately vulnerable, there is no WAF in front, secrets are not stored in a proper vault, and the container base image is not independently verified. No combination of YAML field changes can close these gaps because they require code fixes, operational controls, and infrastructure that simply is not modelled. The one risk no YAML edit can ever close is **cross-site-scripting**: it lives inside the application's HTML rendering logic, which is entirely outside what the threat model YAML describes.

---

## Bonus

### Severity table (auth flow model)

| Severity | Count |
|----------|-------|
| critical | 0 |
| high     | 0 |
| elevated | 2 |
| medium   | 19 |
| low      | 8 |
| **Total** | **29** |

### Three risks the auth model surfaced that the baseline did not

**1. sql-nosql-injection (elevated) — T (Tampering)**
Rule ID: `sql-nosql-injection`. The Login Endpoint sends user-supplied input to the Credential Store over a SQL protocol. If input is not sanitised, an attacker can manipulate the query to bypass authentication or extract the entire user table. Mitigation: use parameterised queries or a prepared-statement ORM and never interpolate user input into SQL strings.

**2. unguarded-access-from-internet (elevated) — S (Spoofing)**
Rule ID: `unguarded-access-from-internet`. The Login Endpoint and Admin Endpoint are reachable directly from the internet-trust-boundary asset (the browser) without any intermediate protection layer (no WAF, no rate limiter, no IP filter modelled). An attacker can probe or brute-force the login endpoint without friction. Mitigation: add a WAF or an API gateway as an explicit asset in front of both endpoints, with `ip_filtered: true` or a rate-limiting annotation.

**3. missing-identity-propagation (medium) — R (Repudiation)**
Rule ID: `missing-identity-propagation`. The call from the Login Endpoint to the JWT Service does not carry `enduser-identity-propagation` as its authorisation value, meaning the model cannot prove that the end-user identity is preserved across that internal hop. If the JWT Service does not receive and embed the verified user identity, an internal component could silently issue a token for a different user. Mitigation: declare `authorization: enduser-identity-propagation` on the Issue Token link and ensure the Login Endpoint passes the verified identity to the JWT Service before signing.

### What the feature-level model showed that the architecture model could not

The auth model pinpoints injection and identity-propagation risks that are invisible at the architecture level because the baseline model treats Juice Shop as a single black-box process. Breaking it into Login Endpoint, JWT Service, Credential Store, and Admin Endpoint makes Threagile reason about each internal communication link independently — revealing that the SQL channel to the credential store has no injection guard and that user identity is not explicitly propagated when the token is signed. An architecture-level model can only tell you that the app as a whole handles credentials; a feature-level model shows exactly which internal call is the weak link.
