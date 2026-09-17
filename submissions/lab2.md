## Task 1

### Baseline threat model

The baseline Juice Shop architecture was analyzed with Threagile 0.9.1 using `labs/lab2/threagile-model.yaml`.

The model generated the following outputs:

* `report.pdf`
* `risks.json`
* `risks.xlsx`
* `stats.json`
* `data-flow-diagram.png`
* `data-asset-diagram.png`
* `technical-assets.json`
* `tags.xlsx`

The Threagile run completed successfully. The `Fontconfig error: No writable cache directories` messages did not prevent report generation.

### Severity table

| Severity  |  Count |
| --------- | -----: |
| Critical  |      0 |
| High      |      0 |
| Elevated  |      4 |
| Medium    |     14 |
| Low       |      5 |
| **Total** | **23** |

### Top five risks

| # | Severity | Rule ID                      | Technical asset |
| - | -------- | ---------------------------- | --------------- |
| 1 | Elevated | `unencrypted-communication`  | `user-browser`  |
| 2 | Elevated | `unencrypted-communication`  | `reverse-proxy` |
| 3 | Elevated | `missing-authentication`     | `juice-shop`    |
| 4 | Elevated | `cross-site-scripting`       | `juice-shop`    |
| 5 | Medium   | `cross-site-request-forgery` | `juice-shop`    |

### STRIDE mapping

| Risk                                          | STRIDE                         | Reason                                                                                                                                        |
| --------------------------------------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `unencrypted-communication` — `user-browser`  | **I — Information Disclosure** | Clear-text communication can expose sensitive data to an attacker who can observe the network traffic.                                        |
| `unencrypted-communication` — `reverse-proxy` | **I — Information Disclosure** | Unencrypted communication between components can allow an attacker to intercept information transmitted between them.                         |
| `missing-authentication` — `juice-shop`       | **S — Spoofing**               | Without authentication, an attacker may be able to act as another user or access functionality without proving their identity.                |
| `cross-site-scripting` — `juice-shop`         | **I — Information Disclosure** | XSS can allow attacker-controlled script to execute in a user's browser and potentially access information available to that browser context. |
| `cross-site-request-forgery` — `juice-shop`   | **T — Tampering**              | CSRF can cause an authenticated user's browser to send unintended requests that modify application state.                                     |

### Trust-boundary crossing

**Arrow:** `Direct to App (no proxy)` — User Browser → Juice Shop Application (top-five risk #1, `unencrypted-communication`).

**Boundary crossed:** This arrow goes straight from the **Internet** trust boundary (where `user-browser` lives) into the **Container Network** trust boundary (where `juice-shop` lives), skipping the **Host** boundary entirely — it bypasses the reverse proxy that would otherwise terminate TLS and add security headers.

**Why it is worth an attacker's time:** the flow carries authentication data (credentials, session token) in clear-text HTTP, directly into the innermost trust boundary, with none of the protections (TLS termination, header hardening) that the reverse-proxy path provides. Any attacker positioned to observe the network between the browser and the container — e.g., on a shared LAN or a compromised intermediate host — can read session tokens and credentials off the wire and hijack an authenticated session immediately, without needing to find or exploit any application-level bug first.

## Task 2

### Hardening the model

`labs/lab2/threagile-model-secure.yaml` was created as a copy of the baseline model with three changes:

1. **No clear-text traffic into the application.** Both communication links that terminate at `juice-shop` were changed from `protocol: http` to `protocol: https`:
   - `Direct to App (no proxy)` (User Browser → Juice Shop Application)
   - `To App` (Reverse Proxy → Juice Shop Application)
2. **Reverse-proxy-to-app authentication declared.** The `To App` link's `authentication: none` was changed to `authentication: client-certificate` (mutual TLS between the proxy and the app), so the internal hop is no longer anonymous.
3. **Encryption at rest.** `encryption: none` was changed to `encryption: data-with-symmetric-shared-key` on both the `Juice Shop Application` technical asset and the `Persistent Storage` technical asset.

The secure run (`labs/lab2/output-secure/`) completed successfully and produced the full set of outputs, including `risks.xlsx` and `report.pdf` (title stayed under 31 characters, so the Excel/PDF export step did not fail).

### Severity comparison

| Severity  | Baseline | Secure | Delta   |
| --------- | -------: | -----: | ------: |
| Critical  |        0 |      0 |       0 |
| High      |        0 |      0 |       0 |
| Elevated  |        4 |      1 |      -3 |
| Medium    |       14 |     12 |      -2 |
| Low       |        5 |      5 |       0 |
| **Total** |   **23** | **18** |  **-5** |

The total dropped from 23 to 18 — a fall of about 22%, roughly a fifth, not to zero (as expected).

### Rules that disappeared (`gone:`)

| Rule ID                    | Field change that removed it                                                                                                                                 |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `missing-authentication`    | `To App` link (Reverse Proxy → Juice Shop): `authentication: none` → `authentication: client-certificate`.                                                                                                          |
| `unencrypted-asset`         | `Juice Shop Application` and `Persistent Storage`: `encryption: none` → `encryption: data-with-symmetric-shared-key` on both assets (2 findings removed).                                                          |
| `unencrypted-communication` | Both links into the app: `Direct to App (no proxy)` and `To App`: `protocol: http` → `protocol: https` (2 findings removed).                                                                                        |

### Rules that still fire

- **`cross-site-scripting`** (elevated, Juice Shop Application) — XSS is a server-side input-validation/output-encoding defect in the application's own code (Juice Shop reflects/stores unsanitized user input by design). No transport-encryption, authentication, or at-rest-encryption field in the YAML model changes how the app handles untrusted input, so hardening the architecture description cannot remove it — it requires fixing the application code (output encoding, CSP).
- **`cross-site-request-forgery`** (medium, Juice Shop Application) — CSRF is mitigated by anti-CSRF tokens or `SameSite` cookie policy enforced in application logic, not by an architectural attribute like link encryption or asset encryption at rest. Threagile flags any state-changing, session-authenticated endpoint reachable from a browser as CSRF-prone regardless of transport security.

### What is left

What survives hardening is mostly code-level and process risk that an architecture-level YAML edit cannot reach: injection/logic-class flaws (XSS, CSRF, SSRF), missing security tooling that the model doesn't represent as an asset (WAF, secrets vault, identity store, build pipeline), and supply-chain risk from the base container image (`container-baseimage-backdooring`). Closing these needs secure coding practices, dependency/image scanning, and deploying additional controls such as a WAF or vault — none of which is expressible by toggling the `protocol`, `authentication`, or `encryption` fields on existing assets. **`cross-site-scripting` is the one no YAML edit can close**: it comes from how Juice Shop's own code renders user input (deliberately vulnerable by design), so it can only be fixed by changing the application, not the threat model.

## Bonus

### Model

A second, smaller model, `labs/lab2/threagile-model-auth.yaml`, was built from the Threagile stub covering only the login and admin-access path: `User Browser`, `Login Endpoint`, `Token Service`, `Admin Endpoint`, `Credential Store` (5 technical assets), five communication links (`Submit Credentials`, `Access Admin API`, `Verify Credentials`, `Request Token Issuance`, `Verify Token And Role`), and four data assets (`Login Credentials`, `User Credential Hashes`, `JWT Access Token`, `JWT Signing Key` — the signing key modeled as its own data asset). Every communication link declares non-`none` `authentication` and `authorization` values, and the `Admin Endpoint` sits behind an authorization check expressed on its incoming link (`Access Admin API`: `authorization: enduser-identity-propagation`) and its outgoing verification call to the Token Service (`Verify Token And Role`: `authorization: technical-user`).

The run (`labs/lab2/output-auth/`) completed successfully.

### Severity table

| Severity  | Count  |
| --------- | -----: |
| Critical  |      0 |
| High      |      0 |
| Elevated  |      6 |
| Medium    |     16 |
| Low       |      5 |
| **Total** | **27** |

### Three auth-specific risks not seen in the baseline architecture model

| Rule ID                        | STRIDE                | Mitigation                                                                                                                               |
| ------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sql-nosql-injection`           | **T — Tampering**       | Use parameterized queries/prepared statements for the `Verify Credentials` call so submitted credentials can never alter the query issued against the Credential Store.               |
| `unguarded-access-from-internet` | **D — Denial of Service** | Put the Login and Admin endpoints behind a reverse proxy/WAF with rate limiting instead of exposing them directly to the internet-facing browser.                                     |
| `missing-identity-propagation`  | **S — Spoofing**        | Propagate the authenticated end-user's identity (e.g., a signed claim) from the Login Endpoint to the Token Service so it cannot be tricked into issuing a token for an arbitrary user. |

### What a feature-level model shows that the architecture-level one could not

Treating the login and admin path as one opaque "Juice Shop Application" box (as in the baseline) hides the internal call graph entirely, so risks tied to the *specific* internal hop — the exact query used to check credentials, and whether the identity making a service-to-service call to the token issuer is actually propagated — never surface. Modeling the Login Endpoint, Token Service, Admin Endpoint, and Credential Store as separate assets makes those internal trust boundaries and data flows visible, so Threagile can reason about them individually instead of collapsing them into a single undifferentiated component.
