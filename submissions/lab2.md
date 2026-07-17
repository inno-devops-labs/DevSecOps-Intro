## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High     | 0 |
| Elevated | 4 |
| Medium   | 14|
| Low      | 5 |
| **Total**| 23|

### Top 5 risks (paste from `jq` output)
1. **missing-authentication** — Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application; severity elevated; affecting juice-shop
2. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity elevated; affecting juice-shop
3. **unencrypted-communication** — Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data; severity elevated; affecting user-browser
4. **unencrypted-communication** — Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application; severity elevated; affecting reverse-proxy
5. **unnecessary-technical-asset** — Unnecessary Technical Asset named Persistent Storage; severity low; affecting persistent-storage

### STRIDE mapping (Lecture 2 slide 7)
For each top-5 risk, name the STRIDE letter(s) it primarily violates:
- Risk 1: **Spoofing (S)** — Missing authentication on a critical communication link means the application does not verify the true identity of the caller. This allows an attacker to spoof a legitimate connection or a trusted reverse proxy to send unauthorized traffic to the backend.
- Risk 2: **Tampering (T)** — Cross-Site Scripting (XSS) allows an attacker to inject and execute malicious JavaScript into the web pages viewed by users. This directly tampers with the application code execution context inside the victim's browser session.
- Risk 3: **Information Disclosure (I)** — Transmitting highly sensitive data like login credentials, session IDs, and tokens over an unencrypted connection (HTTP) allows anyone capturing network traffic to sniff the data in plain text, causing a massive data breach.
- Risk 4: **Information Disclosure (I)** — Even if it occurs internally behind a reverse proxy, unencrypted communication means that an attacker who compromises the local network environment or performs lateral movement can eavesdrop on internal application traffic.
- Risk 5: **Information Disclosure (I)** — Maintaining a persistent storage asset that the architecture marks as unnecessary increases the overall data attack surface. If left unmonitored or unhardened, it presents a risk where stale or unprotected data could be exposed to unauthorized parties.

### Trust Boundary Observation
Looking at `data-flow-diagram.png`, the arrow crossing a trust boundary that appears in my top-5 risks is the **Direct to App (no proxy)** link, which travels over plain **http** from the **User Browser** (Internet boundary) directly into the **Juice Shop Application** (Container Network boundary). 
This arrow is particularly attractive to an attacker because it represents unencrypted, unauthenticated public traffic bypassing the reverse proxy perimeter completely. It allows an attacker on an untrusted network to easily perform a Man-in-the-Middle (MitM) attack to sniff highly sensitive authentication tokens, session cookies, and credentials in plain text.

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0        | 0      | 0 |
| High     | 0        | 0      | 0 |
| Elevated | 4        | 2      | -2|
| Medium   | 14       | 13     | -1|
| Low      | 5        | 5      | 0 |
| **Total**| **23** | **20** | **-3**|

### Which rules are GONE in the secure variant?
1. `unencrypted-communication` — fixed by changing the protocol from HTTP to HTTPS on the user-to-app and webhook communication links.
2. `unencrypted-asset` — fixed by applying `data-with-symmetric-shared-key` encryption to the Persistent Storage database volume.
3. `sql-injection` — fixed by explicitly declaring the use of prepared statements and parameterized queries in the database communication link description.

### Which rules are STILL THERE in the secure variant?
1. `missing-authentication` — Changing network protocols and encrypting the database does not automatically verify user identity. The application endpoints are still globally exposed without strong authentication checks.
2. `cross-site-scripting` — Infrastructure and architectural changes do not fix application-layer input sanitization. This risk remains because the application code still reflects untrusted user input without encoding it.

### Honesty check
Did the total drop more than 50%? **No.** The total only dropped from 23 to 20. This reveals that while infrastructure hardening (HTTPS, DB encryption) is crucial, the vast majority of application risk lies in business logic, access control, and input validation. Those vulnerabilities require deep code-level fixes rather than just architectural configuration tweaks.

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High     | 0 |
| Elevated | 5 |
| Medium   | 8 |
| Low      | 3 |
| **Total**| 16|

### Three auth-specific risks (NOT in the baseline model's top 5)
For each, name:
- The rule ID Threagile fires
- The STRIDE letter
- A 1-2 sentence mitigation in plain English

1. **missing-authentication** — STRIDE: **S (Spoofing)** — Mitigation: Implement strict authentication (e.g., using secure service tokens or mutual TLS) for the `db-query` communication link to ensure that only the verified `auth-api` can access the `user-db`.
2. **missing-hardening** — STRIDE: **T (Tampering)** — Mitigation: Configure the `auth-api` with modern security headers (such as CSP, HSTS, and X-Frame-Options) to protect the integrity of the application's response and mitigate client-side attacks.
3. **cross-site-scripting** — STRIDE: **T (Tampering)** — Mitigation: Apply rigorous input sanitization and context-aware output encoding on the `admin-endpoint` to prevent the injection and execution of malicious scripts within the administrative dashboard.

### Reflection (2-3 sentences)
Creating this focused model helped to look at how the app’s internal parts work together, rather than just looking at the overall network. While the baseline model mostly found risks at the front door (where users connect), this auth-specific model uncovered hidden problems inside the system—like unprotected database access and weak security settings on internal APIs—that the broader model missed.
