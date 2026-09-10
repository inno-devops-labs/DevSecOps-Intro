# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

Image: `threagile/threagile:0.9.1` (binary self-reports 1.0.0).
Models in this PR: `labs/lab2/threagile-model.yaml` (baseline, given),
`labs/lab2/threagile-model-secure.yaml`, `labs/lab2/threagile-model-auth.yaml`.

## Task 1

### Severity counts (2.2)

Command: `jq '[.[].severity] | group_by(.) | map({severity: .[0], count: length})' labs/lab2/output/risks.json`

| Severity | Count |
|----------|-------|
| critical | 0 |
| high | 0 |
| elevated | 4 |
| medium | 14 |
| low | 5 |
| **Total** | **23** |

### Top five risks (2.3)

| # | Severity | Rule ID (`category`) | Most relevant asset |
|---|----------|----------------------|---------------------|
| 1 | elevated | `cross-site-scripting` | `juice-shop` |
| 2 | elevated | `missing-authentication` | `juice-shop` (link *To App* from *Reverse Proxy*) |
| 3 | elevated | `unencrypted-communication` | `user-browser` (link *Direct to App (no proxy)*) |
| 4 | elevated | `unencrypted-communication` | `reverse-proxy` (link *To App*) |
| 5 | medium | `missing-vault` | `juice-shop` |

### STRIDE mapping

1. **`cross-site-scripting` → T (Tampering).** An attacker injects script that is stored and
   later rendered in other users' browsers, tampering with the content and behaviour the app
   delivers to those clients.
2. **`missing-authentication` → S (Spoofing).** The reverse-proxy→app hop authenticates as
   `none`, so any process on the host can open that connection and impersonate the proxy to the
   application.
3. **`unencrypted-communication` (browser→app direct) → I (Information Disclosure).** Plain HTTP
   on port 3000 carries `session-id` / token data in clear text, so anyone on the path reads
   credentials and live sessions off the wire.
4. **`unencrypted-communication` (proxy→app) → I (Information Disclosure).** The internal
   forward is also plain HTTP; tokens and catalog data are exposed to anything sniffing the host
   network between the proxy and the container.
5. **`missing-vault` → I (Information Disclosure).** With no secret store, the JWT signing key
   and other secrets live in env vars, config, or disk and leak through logs, backups, or a file
   read.

### Trust-boundary crossing

The arrow **`Direct to App (no proxy)`** runs from **User Browser** (inside the *Internet*
boundary) straight to **Juice Shop Application** (inside the nested *Container Network*
boundary), crossing *Internet → Host → Container Network* in one hop and bypassing the
TLS-terminating reverse proxy entirely. It is worth an attacker's time because it is plain HTTP
and it carries authentication data (`tokens-sessions`): a passive eavesdropper on any segment
(shared Wi-Fi, the host bridge) harvests valid session tokens with no cryptography to defeat,
turning a network position directly into account takeover. This is top-five risk #3
(`unencrypted-communication` at `user-browser`).

## Task 2

Hardening applied to `threagile-model-secure.yaml`:

| Change | Field |
|--------|-------|
| `Direct to App (no proxy)` browser→app now encrypted | `protocol: http` → `https` |
| `To App` proxy→app now encrypted | `protocol: http` → `https` |
| `To App` proxy→app now authenticates | `authentication: none` → `client-certificate` (and `authorization: none` → `technical-user`) |
| Juice Shop app encrypted at rest | `encryption: none` → `data-with-symmetric-shared-key` |
| Persistent Storage encrypted at rest | `encryption: none` → `data-with-symmetric-shared-key` |

### Baseline vs secure counts

| Severity | Baseline | Secure | Delta |
|----------|----------|--------|-------|
| critical | 0 | 0 | 0 |
| high | 0 | 0 | 0 |
| elevated | 4 | 1 | -3 |
| medium | 14 | 12 | -2 |
| low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **-5** |

23 → 18 is a drop of ~22%, "roughly a fifth".

### Rules in `gone:` and the field that removed each

| Rule ID | Field change that removed it |
|---------|------------------------------|
| `unencrypted-communication` | `protocol` set to `https` on both inbound links (`Direct to App (no proxy)`, `To App`) — no in-scope link now carries clear text. |
| `missing-authentication` | `authentication: client-certificate` on the reverse-proxy→app `To App` link (was `none`). |
| `unencrypted-asset` | `encryption: data-with-symmetric-shared-key` on `juice-shop` and `persistent-storage` (was `none`). |

### Two rules that still fire

- **`cross-site-scripting` (`juice-shop`).** It is driven by `custom_developed_parts: true` on
  the application, not by any transport or storage attribute. No protocol/encryption/auth field
  in the YAML describes output encoding in the app code, so no edit here can clear it.
- **`server-side-request-forgery` (`juice-shop` → `webhook-endpoint`).** It fires because the
  app still has an outbound `To Challenge WebHook` link to an internet target. The hardening
  brief only covers the two inbound links and encryption at rest; removing the webhook asset was
  out of scope, so the SSRF path remains.

### What is left, and what it would take

The residual 18 are application- and operations-layer risks that architecture attributes cannot
express: XSS and CSRF in the app code, SSRF via the webhook, missing second factor, container
base-image backdooring, missing build infrastructure, missing hardening, and no secret vault.
Closing them needs work outside the model — output encoding and anti-CSRF tokens in the
source, an egress allow-list for the webhook, a 2FA rollout, pinned and scanned base images, a
CI pipeline producing an SBOM, and an actual secrets manager. **`cross-site-scripting` is the
one no YAML edit can close:** it is a property of the Juice Shop source code, and Threagile will
report it for any custom-developed web application regardless of how the architecture is drawn.

## Bonus

`threagile-model-auth.yaml`, written from `-create-stub-model`. Assets: `user-browser`,
`login-endpoint`, `token-verifier`, `admin-endpoint`, `credential-store`, `keystore` (6).
Communication links: `Login Request`, `Admin Action`, `Verify Credentials`,
`Read Signing Key (issue)`, `Read Signing Key (verify)`, `Check Token` (6) — each carries
`authentication` and `authorization`. Data assets: `login-credentials`, `jwt-signing-key`,
`session-token`, `admin-audit-log` (4); the JWT signing key is its own data asset stored only in
`keystore`. The admin endpoint's `Check Token` link to `token-verifier` uses
`authorization: enduser-identity-propagation` — the JWT role-claim check the description points
to.

### Severity table

Command: `jq '[.[].severity] | group_by(.) | map({severity: .[0], count: length})' labs/lab2/output-auth/risks.json`

| Severity | Count |
|----------|-------|
| critical | 0 |
| high | 1 |
| elevated | 5 |
| medium | 20 |
| low | 3 |
| **Total** | **29** |

### Three risks the baseline architecture model did not surface

| Rule ID | STRIDE | Where | One-sentence mitigation |
|---------|--------|-------|-------------------------|
| `sql-nosql-injection` | T (Tampering) | `login-endpoint` → `credential-store` | Use parameterised queries / an ORM for the credential lookup so submitted usernames can never alter the query. |
| `missing-identity-propagation` | E (Elevation of Privilege) | `login-endpoint` | Propagate the authenticated end-user identity (not a shared technical user) on calls that act on a user's behalf, and authorize each request against it. |
| `missing-vault-isolation` | I (Information Disclosure) | `keystore` | Run the secret store on its own isolated runtime/network segment so a compromise of an app container does not expose the JWT signing key. |

(Also new versus the baseline: `missing-network-segmentation`, `unguarded-access-from-internet`,
`wrong-communication-link-content`.)

### What the feature-level model showed that the architecture model could not

Splitting authentication into login, key retrieval, token verification, and an admin check made
the JWT signing key a first-class asset with its own blast radius, so Threagile raised
key-isolation and injection risks on the exact hop that handles credentials — detail the single
"Juice Shop Application" box in the baseline collapsed into one generic app node. It also showed
that the admin endpoint's protection depends on a separate verifier service, i.e. an
authorization decision that lives on a communication link rather than inside one asset.

## Commands run

```
docker run --rm -v "$(pwd)/labs/lab2":/app/work threagile/threagile:0.9.1 \
  -model /app/work/threagile-model.yaml -output /app/work/output
docker run --rm -v "$(pwd)/labs/lab2":/app/work threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-secure.yaml -output /app/work/output-secure
docker run --rm -v "$(pwd)/labs/lab2":/app/work threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-auth.yaml -output /app/work/output-auth
```

`gone:` / `new:` diff:

```
gone:
missing-authentication
unencrypted-asset
unencrypted-communication
new:
(none)
```
