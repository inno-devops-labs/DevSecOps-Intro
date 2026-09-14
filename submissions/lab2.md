# Lab 2 — STRIDE Threat Modeling with Threagile

## Task 1

Baseline model command:

```bash
docker run --rm -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model.yaml -output /app/work/output
```

Generated files:

```text
data-asset-diagram.png
data-flow-diagram.png
report.pdf
risks.json
risks.xlsx
stats.json
tags.xlsx
technical-assets.json
```

Total risks:

```text
23
```

Severity table:

| Severity | Count |
| --- | ---: |
| elevated | 4 |
| medium | 14 |
| low | 5 |

Top five risks:

| Severity | Rule ID | Most relevant asset | STRIDE | Why |
| --- | --- | --- | --- | --- |
| elevated | `unencrypted-communication` | `user-browser` | I | The direct browser-to-app link carries session/authentication data over HTTP, so an observer on the path could read sensitive traffic. |
| elevated | `unencrypted-communication` | `reverse-proxy` | I | The reverse-proxy-to-app link is also HTTP, so traffic that has already crossed the edge can still be disclosed inside the host/container path. |
| elevated | `missing-authentication` | `juice-shop` | S | The app does not authenticate the reverse proxy on the `To App` link, so another component could pretend to be that trusted upstream. |
| elevated | `cross-site-scripting` | `juice-shop` | T | XSS lets attacker-controlled script alter what the browser sees and does in the context of the Juice Shop origin. |
| medium | `missing-vault` | `juice-shop` | I | Secrets owned by or used by the application are not modeled as protected by a vault, so disclosure impact remains high if the app or config is read. |

Trust-boundary crossing worth attacking: `User Browser -> Juice Shop Application` via `Direct to App (no proxy)`. It crosses from the untrusted `Internet` boundary into the nested `Container Network` boundary and appears in the top-five as `unencrypted-communication`; that arrow is valuable because it can carry session IDs/tokens and user actions directly to the vulnerable application without the reverse proxy controls.

## Task 2

Secure model changes were made in `labs/lab2/threagile-model-secure.yaml`:

- `Direct to App (no proxy)`: `protocol: http` changed to `protocol: https`.
- `Reverse Proxy -> To App`: `protocol: http` changed to `protocol: https`.
- `Reverse Proxy -> To App`: `authentication: none` changed to `authentication: client-certificate`, and `authorization: none` changed to `authorization: technical-user`.
- `Juice Shop Application`: `encryption: none` changed to `encryption: data-with-symmetric-shared-key`.
- `Persistent Storage`: `encryption: none` changed to `encryption: data-with-symmetric-shared-key`.

Secure model command:

```bash
docker run --rm -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-secure.yaml -output /app/work/output-secure
```

Risk count comparison:

| Severity | Baseline | Secure | Delta |
| --- | ---: | ---: | ---: |
| elevated | 4 | 1 | -3 |
| medium | 14 | 12 | -2 |
| low | 5 | 5 | 0 |
| total | 23 | 18 | -5 |

Rule diff:

```text
gone:
missing-authentication
unencrypted-asset
unencrypted-communication
new:
```

Removed rules and field changes:

| Gone rule ID | Field change that removed it |
| --- | --- |
| `unencrypted-communication` | Both inbound application links were changed from clear-text `http` to encrypted `https`. |
| `missing-authentication` | `Reverse Proxy -> To App` now declares `authentication: client-certificate`. |
| `unencrypted-asset` | The application and persistent storage assets now use `encryption: data-with-symmetric-shared-key`. |

Rules that still fire:

- `cross-site-scripting` still fires because the application remains OWASP Juice Shop, a deliberately vulnerable app. Transport encryption and at-rest encryption do not remove XSS sinks in the application code.
- `server-side-request-forgery` still fires because the model still has server-side outbound/request-forwarding flows: the app can call the webhook endpoint, and the reverse proxy forwards to the app. The secure edits protect transport and identity but do not remove or constrain those request capabilities.

The total dropped from 23 to 18, roughly one fifth, which is the expected shape: configuration hardening removed clear-text transport, missing link authentication, and unencrypted-at-rest findings, but it did not make the application safe. The remaining risk is mostly application and architecture behavior: XSS, CSRF, SSRF, missing hardening, missing WAF, missing vault, and supply-chain/base-image concerns. Closing those would require application fixes, edge controls, secret-management infrastructure, image provenance controls, and runtime policy, not only YAML edits. One risk no YAML edit can truly close is Juice Shop's real XSS behavior; the model can document or suppress it, but only code fixes or compensating runtime controls can reduce it in the running app.
