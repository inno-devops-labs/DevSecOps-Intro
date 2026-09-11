# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

**Environment:**
- Windows 11 host, Docker Desktop 29.7.2.
- Threagile image `threagile/threagile:0.9.1` (`sha256:abb9eccb111a2059c4876759a24245db02ad295b1608d3a4634ec250f38d9640`). The binary inside reports `Version: 1.0.0 (20240730113903)`.
- `jq` is not installed here, so the 2.2, 2.3 and 2.5 queries ran as a small Python script with the same logic: array length, group by `severity`, a stable sort by the explicit `critical, high, elevated, medium, low` order, and a set difference of `category` values.

## Task 1

### 2.1 Baseline run

```bash
docker run --rm -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model.yaml -output /app/work/output
ls labs/lab2/output/
```

```text
data-asset-diagram.png  data-flow-diagram.png  report.pdf  risks.json  risks.xlsx  stats.json  tags.xlsx  technical-assets.json
```

The run exited with code 0. Apart from repeated `Fontconfig error: No writable cache directories` lines, it printed no errors.

### 2.2 Severity counts

`length` of `risks.json`: **23**

| Severity | Count |
|---|---|
| critical | 0 |
| high | 0 |
| elevated | 4 |
| medium | 14 |
| low | 5 |
| **Total** | **23** |

`stats.json` has the same numbers, all with status `unchecked`.

### 2.3 Top five

```text
elevated	missing-authentication	juice-shop
elevated	unencrypted-communication	user-browser
elevated	unencrypted-communication	reverse-proxy
elevated	cross-site-scripting	juice-shop
medium	server-side-request-forgery	juice-shop
```

| # | Rule (asset, link) | STRIDE | Why |
|---|---|---|---|
| 1 | `missing-authentication` (`juice-shop`, link `reverse-proxy>to-app`) | **E** — Elevation of Privilege | The app accepts every request on the proxy link without checking who sent it. Anything that reaches port 3000 inside the Docker network gets the proxy's level of trust and skips the proxy's TLS and header controls. |
| 2 | `unencrypted-communication` (`user-browser`, link `user-browser>direct-to-app-no-proxy`) | **I** — Information Disclosure | Session IDs and JWTs (`tokens-sessions`) travel over plain HTTP on port 3000, so anyone on the network path can read them and replay the session. |
| 3 | `unencrypted-communication` (`reverse-proxy`, link `reverse-proxy>to-app`) | **I** — Information Disclosure | TLS ends at the proxy and the same tokens continue to the container in clear text, readable by anything that can sniff the host's Docker bridge. |
| 4 | `cross-site-scripting` (`juice-shop`) | **T** — Tampering | A script injected through, for example, a product review changes the page other users load and runs inside their session. |
| 5 | `server-side-request-forgery` (`juice-shop`, link `juice-shop>to-challenge-webhook`) | **I** — Information Disclosure | The server sends outbound requests to a configurable webhook URL, and a server that fetches attacker-influenced URLs can be pointed at internal addresses and return what it finds there. |

The STRIDE letters are Threagile's own classification, taken from the `STRIDE` column of `risks.xlsx`.

### Trust-boundary crossing

**Arrow:** User Browser → Juice Shop Application, link **"Direct to App (no proxy)"**, protocol `http`. It is row 2 of the top five (`unencrypted-communication@user-browser>direct-to-app-no-proxy`).

**Boundaries crossed:** the arrow starts in the **Internet** boundary and ends inside **Container Network**. In one hop it crosses Internet → Host and Host → Container Network, and it never passes the reverse proxy.

**Why it is worth an attacker's time:**
- It is the only path from the untrusted zone straight into the application. It skips the proxy's TLS termination and security headers.
- It carries session tokens in clear text. Its impact is `high`, the highest in the top five.
- Nothing sits between the untrusted zone and the app, so it is the shortest route for the injection payloads Juice Shop is built to be vulnerable to.

Binding the container to `127.0.0.1` in Lab 1 is exactly the control that removes the Internet end of this arrow.

## Task 2

### 2.4 Hardening changes

`labs/lab2/threagile-model-secure.yaml` is a copy of the baseline with these field changes and nothing else. No assets or links were added.

| Asset / link | Field | Baseline | Secure |
|---|---|---|---|
| model | `title` | `OWASP Juice Shop Threat Model` | `OWASP Juice Shop Secure Model` (29 characters) |
| link `Direct to App (no proxy)` (browser → app) | `protocol` | `http` | `https` |
| link `To App` (reverse proxy → app) | `protocol` | `http` | `https` |
| link `To App` | `authentication` | `none` | `client-certificate` |
| link `To App` | `authorization` | `none` | `enduser-identity-propagation` |
| asset `juice-shop` | `encryption` | `none` | `transparent` |
| asset `persistent-storage` | `encryption` | `none` | `transparent` |

What the values mean:
- **`client-certificate`:** the proxy authenticates to the app with mutual TLS.
- **`enduser-identity-propagation`:** the proxy passes the user's JWT through, and the app keeps authorising on the end user.
- **`transparent`:** disk or volume encryption (BitLocker on the host, LUKS for the volume) that the application does not see.

The two link descriptions were updated to match the new values.

### 2.5 Secure run and diff

```bash
docker run --rm -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-secure.yaml -output /app/work/output-secure
```

The run exited with code 0 and wrote the full set of outputs, including `report.pdf` and `risks.xlsx`, to `labs/lab2/output-secure/`. `length` of the secure `risks.json`: **18**.

| Severity | Baseline | Secure | Delta |
|---|---|---|---|
| critical | 0 | 0 | 0 |
| high | 0 | 0 | 0 |
| elevated | 4 | 1 | −3 |
| medium | 14 | 12 | −2 |
| low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **−5 (−22 %)** |

```text
gone:
missing-authentication
unencrypted-asset
unencrypted-communication
new:
```

| Rule gone | Instances | Field change that removed it |
|---|---|---|
| `unencrypted-communication` | 2 → 0 | `protocol: http` → `https` on `Direct to App (no proxy)` and on `To App` |
| `missing-authentication` | 1 → 0 | `authentication: none` → `client-certificate` on `To App` |
| `unencrypted-asset` | 2 → 0 | `encryption: none` → `transparent` on `juice-shop` and `persistent-storage` |

### Two rules that still fire

- **`cross-site-scripting`** (elevated, `juice-shop`). Threagile raises it for every web application with custom-developed parts, because XSS is a defect in how the code handles and encodes user input. Transport and at-rest encryption do nothing against a script stored in a product review and served to the next visitor. The only YAML "fix" would be to misdescribe the asset's technology.
- **`container-baseimage-backdooring`** (medium, `juice-shop`). It fires for any asset with `machine: container`, because the risk sits inside the image: its base layers and npm dependencies. TLS and disk encryption faithfully protect a backdoored image. Only provenance controls address it, such as pinning by digest, SBOMs, scanning and signing (Labs 4, 5 and 8), and those are processes outside the model.

### What is left

The 18 remaining risks fall into four groups:
- **Code-level:** XSS, CSRF, SSRF.
- **Supply chain and build:** base-image backdooring, missing build infrastructure.
- **Missing security components and operational gaps:** hardening, vault, 2FA, WAF, identity store.
- **Model hygiene (the four `low` findings):** `unnecessary-data-transfer` and `unnecessary-technical-asset`. They point at gaps in the model rather than in the system.

Apart from the model-hygiene findings, which a more complete model would clear, none of them depends on an enum value that a model edit can flip. Closing them takes changes in the code with tests to prove them, pipeline controls around the image, and real components (a vault, a WAF, an identity provider with 2FA) added to the architecture and then to the model. `cross-site-scripting` is one that no YAML edit can close: the flaw lives in Juice Shop's source. Even after a fix, the model can only record it as `mitigated` under `risk_tracking`, and it still appears in `risks.json`.

## Bonus

### The model

I wrote `labs/lab2/threagile-model-auth.yaml` from the `-create-stub-model` skeleton. It covers only the login path.

**Technical assets (6):**

| Asset | What it is |
|---|---|
| `user-browser` | The single-page app; keeps the JWT in localStorage |
| `login-endpoint` | `POST /rest/user/login` |
| `token-issuer` | `lib/insecurity`, signs the JWT |
| `jwt-verifier` | `security.isAuthorized()`: express-jwt signature check in front of `/api/Users` |
| `admin-endpoint` | The `/api/Users` handler that returns the user list |
| `credential-store` | The SQLite `Users` table |

**Data assets (4):**
- `user-credentials`
- `jwt-signing-key`: its own `strictly-confidential` data asset, stored only in `token-issuer`
- `session-token`
- `admin-user-data`

**Communication links (6).** Every link declares both `authentication` and `authorization`, and none of them uses `none`:

| Link | Protocol | `authentication` | `authorization` |
|---|---|---|---|
| Login Request (browser → login-endpoint) | `https` | `credentials` | `enduser-identity-propagation` |
| Admin API Call (browser → jwt-verifier) | `https` | `token` | `enduser-identity-propagation` |
| Credential Lookup (login-endpoint → credential-store) | `sql-access-protocol` | `credentials` | `technical-user` |
| Issue Token (login-endpoint → token-issuer) | `in-process-library-call` | `externalized` | `enduser-identity-propagation` |
| Authorized Admin Request (jwt-verifier → admin-endpoint) | `in-process-library-call` | `token` | `enduser-identity-propagation` |
| User Management Query (admin-endpoint → credential-store) | `sql-access-protocol` | `credentials` | `technical-user` |

**The admin authorisation check** is the link `Authorized Admin Request`, tagged `authz-check`:
- It is the only incoming link of `admin-endpoint`. The browser has no direct link to the admin endpoint.
- Its description records what the check really does in v20. `server.js` registers `app.get('/api/Users', security.isAuthorized())`, and `isAuthorized()` is express-jwt with the public key. A request without a validly signed JWT gets 401, but nothing checks that the role claim is `admin`.

**Checked against the code.** I copied `server.js`, `lib/insecurity.js` and `routes/login.js` (compiled files under `/juice-shop/build/`) out of the Lab 1 container with `docker cp` and aligned the model with them:
- `routes/login.js`:54 builds the login query with the email and the password hash interpolated into raw SQL.
- `lib/insecurity.js`:46 hard-codes the RSA private key, and line 63 signs tokens with `RS256`.
- `server.js`:353 protects `GET /api/Users` with `isAuthorized()` only. Lines 354-357 deny `PUT` and `DELETE` on `/api/Users/:id` to everyone, so the admin links in the model are read-only.
- The model lists "Customer reads the user list" as an abuse case for the missing role check.

**Trust boundaries:**
- `juice-shop-container` (`network-virtual-lan`) holds the credential store.
- Inside it, `node-process` (`execution-environment`) holds the four code components.
- The shared runtime `juice-shop-runtime` runs those four components.

**One correction after the first run.** In the first version, `token-issuer` was `identity-provider` and `admin-endpoint` was `web-service-rest`. Threagile's `wrong-communication-link-content` rule flagged that an `in-process-library-call` must target a `library`. Both are in fact modules that Express calls in-process, so I switched them to `library`. The results below come from the corrected model.

### Severity table

```bash
docker run --rm -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-auth.yaml -output /app/work/output-auth
```

| Severity | Count |
|---|---|
| critical | 0 |
| high | 0 |
| elevated | 3 |
| medium | 21 |
| low | 1 |
| **Total** | **25** |

### Three risks the baseline model did not surface

| Rule ID | Where | STRIDE | Mitigation |
|---|---|---|---|
| `sql-nosql-injection` (elevated, likelihood `very-likely`) | `login-endpoint` via `Credential Lookup`; a second instance on `admin-endpoint` via `User Management Query` | **T** — Tampering | Query the `Users` table only with bound parameters (Sequelize `where` or `replacements`) instead of the string-interpolated `sequelize.query()` in the login route, which is the bug behind Juice Shop's `' OR 1=1--` admin login. |
| `missing-identity-provider-isolation` (medium, impact `high`) | `credential-store` | **E** — Elevation of Privilege | Move the credential store and token signing into a separate identity service with its own network trust boundary, reachable only from the login and verification paths, so that a compromised product or admin route cannot reach the hashes. |
| `mixed-targets-on-shared-runtime` (medium) | `juice-shop-runtime`: public login route, key-holding token issuer and admin API in one Node.js runtime | **E** — Elevation of Privilege | Move token signing out of the shared runtime into a separate process, vault or HSM that signs on request, so that code execution in any public route no longer exposes the key now hard-coded in `lib/insecurity`. |

The STRIDE letters come from the `STRIDE` column of `labs/lab2/output-auth/risks.xlsx`.

### What the feature-level model showed

The architecture model draws Juice Shop as one `web-server` box, so Threagile could only raise generic risks for it (XSS, CSRF, SSRF) and never saw that the login query, the signing key and the admin API sit side by side in one Node.js process. Splitting the login path into its real parts exposed the injectable SQL link to the credential store, the hard-coded signing key inside the shared runtime and a check in front of `/api/Users` that verifies the token but never the admin role, which is exactly where Juice Shop's login SQL injection, JWT forgery and user-list exposure problems live.
