**# Lab 2 — Submission**

**## Task 1**

**### Severity table (baseline)**

| Severity  | Count  |
| --------- | ------ |
| critical  | 0      |
| high      | 0      |
| elevated  | 4      |
| medium    | 14     |
| low       | 5      |
| **Total** | **23** |

**### Top 5 risks (ranked by severity)**

| Severity | Rule ID                   | Most relevant asset |
| -------- | ------------------------- | ------------------- |
| elevated | missing-authentication    | juice-shop          |
| elevated | unencrypted-communication | user-browser        |
| elevated | unencrypted-communication | reverse-proxy       |
| elevated | cross-site-scripting      | juice-shop          |
| medium   | missing-identity-store    | reverse-proxy       |

**### STRIDE mapping and reasoning**

**1. missing-authentication — S (Spoofing)**

The connection between the reverse proxy and Juice Shop is not authenticated. An attacker who gains access to the internal network could impersonate the proxy and send arbitrary requests to the application as though they originated from a trusted component.

**2. unencrypted-communication (user-browser) — I (Information Disclosure)**

The "Direct to App" connection uses unencrypted HTTP. Session tokens or credentials transmitted through this connection can be intercepted by an attacker on the same network, such as a dorm Wi-Fi, shared office network, or through local ARP spoofing.

**3. unencrypted-communication (reverse-proxy) — I (Information Disclosure)**

The connection between the reverse proxy and the application also uses HTTP. Therefore, even when TLS protects the external connection to the proxy, tokens forwarded over the internal connection remain exposed on the host network between the two processes.

**4. cross-site-scripting — T (Tampering)**

Juice Shop stores product descriptions containing raw HTML without sanitization. A malicious script placed in a product description can execute in the browser of every user who views that product, enabling modification of the rendered page and theft of session tokens stored in localStorage.

**5. missing-identity-store — R (Repudiation)**

The model does not define a dedicated identity store, so Threagile cannot establish that user identities are consistently tracked and auditable. Without a verifiable identity trail, a user could deny performing an action, while no log entry connected to a verified identity would exist to disprove the claim.

**### Trust-boundary crossing worth an attacker's time**

The **"Direct to App (no proxy)"** connection from the User Browser crosses the **Internet → Container Network** trust boundary (with the Host in between) while transmitting session tokens over unencrypted HTTP. This connection is significant because it accesses the application directly without TLS termination. A network-adjacent attacker, such as someone on the same LAN or using a malicious router or ARP poisoning, could capture the session token and replay it to authenticate as the victim without obtaining their credentials. Because this is an optional "no proxy" path, it can also be easy to overlook.

---

**## Task 2**

**### Hardening changes applied to `threagile-model-secure.yaml`**

1. `Direct to App (no proxy)` link: `protocol: http` → `protocol: https`

2. `To App` link (Reverse Proxy → Juice Shop): `protocol: http` → `protocol: https`, `authentication: none` → `authentication: token`, `authorization: none` → `authorization: technical-user`

3. `Juice Shop Application` asset: `encryption: none` → `encryption: data-with-symmetric-shared-key`

4. `Persistent Storage` asset: `encryption: none` → `encryption: data-with-symmetric-shared-key`

**### Severity comparison: baseline vs secure**

| Severity  | Baseline | Secure | Delta  |
| --------- | -------- | ------ | ------ |
| critical  | 0        | 0      | 0      |
| high      | 0        | 0      | 0      |
| elevated  | 4        | 1      | -3     |
| medium    | 14       | 12     | -2     |
| low       | 5        | 5      | 0      |
| **Total** | **23**   | **18** | **-5** |

**### Rules removed (gone)**

| Rule ID                     | Field change that removed it                                                              |
| --------------------------- | ----------------------------------------------------------------------------------------- |
| `missing-authentication`    | `To App` link: `authentication: none` → `authentication: token`                           |
| `unencrypted-communication` | Both links to Juice Shop: `protocol: http` → `protocol: https`                            |
| `unencrypted-asset`         | App and storage assets: `encryption: none` → `encryption: data-with-symmetric-shared-key` |

**###Two rules that still fire**

**cross-site-scripting** — XSS is a vulnerability in the application code rather than in the architecture. Changing fields in the YAML threat model cannot remove the fact that Juice Shop renders product descriptions without sanitization. Resolving this issue requires changes to the application code itself.

**cross-site-request-forgery** — CSRF protection relies on the application's handling of state-changing requests, such as validating the `Origin` header or using CSRF tokens. The model can mark a connection as readonly or specify stronger authentication, but the application itself must implement the required CSRF protections. A YAML modification does not provide those protections.

**### What risk is left, and why it can't go to zero**

The remaining risks are primarily application-level and operational, including XSS, CSRF, the absence of a WAF, insufficient hardening, the lack of a secrets vault, and possible container base-image backdooring. These issues are not determined by network topology or protocol configuration. They exist because the application code is intentionally vulnerable, no WAF is placed in front of it, secrets are not managed through a dedicated vault, and the container base image is not independently verified. These gaps cannot be eliminated through YAML changes alone because they require application fixes, operational measures, and infrastructure that is not represented in the model. The risk that no YAML modification can eliminate is **cross-site-scripting**, since it originates in the application's HTML rendering logic, which is outside the scope of the threat model YAML.

---

**## Bonus**

**### Severity table (auth flow model)**

| Severity  | Count  |
| --------- | ------ |
| critical  | 0      |
| high      | 0      |
| elevated  | 2      |
| medium    | 19     |
| low       | 8      |
| **Total** | **29** |

**### Three risks the auth model surfaced that the baseline did not**



**1. unguarded-access-from-internet (elevated) — S (Spoofing)**

Rule ID: `unguarded-access-from-internet`. The Login Endpoint and Admin Endpoint can be accessed directly from the internet-trust-boundary asset (the browser) without an additional protection layer such as a WAF, rate limiter, or IP filter being represented in the model. This allows attackers to probe or brute-force the login endpoint with little resistance. Mitigation: place a WAF or API gateway in front of both endpoints as an explicit asset, using `ip_filtered: true` or a rate-limiting annotation.

**2. sql-nosql-injection (elevated) — T (Tampering)**

Rule ID: `sql-nosql-injection`. The Login Endpoint passes user-controlled input to the Credential Store through a SQL protocol. If that input is not properly sanitized, an attacker may alter the SQL query to bypass authentication or retrieve the entire user table. Mitigation: use parameterized queries or a prepared-statement ORM and never construct SQL strings by directly interpolating user input.

**3. missing-identity-propagation (medium) — R (Repudiation)**

Rule ID: `missing-identity-propagation`. The request from the Login Endpoint to the JWT Service does not specify `enduser-identity-propagation` as its authorization value. Therefore, the model cannot demonstrate that the verified end-user identity is preserved across this internal connection. If the JWT Service does not receive and include the verified identity in the token, an internal component could potentially issue a token for another user without detection. Mitigation: set `authorization: enduser-identity-propagation` on the Issue Token link and ensure that the Login Endpoint passes the verified identity to the JWT Service before the token is signed.

**### What the feature-level model showed that the architecture model could not**

The authentication model exposes injection and identity-propagation issues that are hidden at the architectural level because the baseline model represents Juice Shop as a single black-box process. Separating it into the Login Endpoint, JWT Service, Credential Store, and Admin Endpoint allows Threagile to analyze each internal communication link independently. This reveals that the SQL connection to the credential store has no injection protection and that user identity is not explicitly propagated during token signing. An architecture-level model can show that the application handles credentials as a whole, whereas the feature-level model identifies the specific internal connection where the weakness occurs.
