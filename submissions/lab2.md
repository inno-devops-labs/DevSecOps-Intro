# Lab 2 — Threat Modeling: STRIDE on Juice Shop with Threagile

Baseline model: `labs/lab2/threagile-model.yaml` · Secure variant: `labs/lab2/threagile-model-secure.yaml` · Auth flow: `labs/lab2/threagile-model-auth.yaml`
Threagile image: `threagile/threagile:0.9.1`.

## Task 1

### Severity counts (2.2)

| Severity | Count |
|----------|------:|
| critical | 0 |
| high | 0 |
| elevated | 4 |
| medium | 14 |
| low | 5 |
| **Total** | **23** |

### Top five risks (2.3)

| Severity | Rule (category) | Most relevant asset |
|----------|-----------------|---------------------|
| elevated | `missing-authentication` | juice-shop |
| elevated | `unencrypted-communication` | user-browser |
| elevated | `unencrypted-communication` | reverse-proxy |
| elevated | `cross-site-scripting` | juice-shop |
| medium | `missing-build-infrastructure` | juice-shop |

### STRIDE mapping of the top five

1. **`missing-authentication` (proxy → app link)** → **S (Spoofing).** The `To App` link declares `authentication: none`, so nothing proves the caller really is the reverse proxy — anyone who reaches the app port can impersonate a trusted upstream.
2. **`unencrypted-communication` (user-browser, `Direct to App` HTTP)** → **I (Information Disclosure).** Credentials, session-id and JWTs travel in clear text on port 3000, so anyone on the path can read them.
3. **`unencrypted-communication` (reverse-proxy → app, HTTP)** → **I (Information Disclosure).** The internal hop from proxy to app is plaintext, exposing the same tokens once traffic is past TLS termination.
4. **`cross-site-scripting` (juice-shop)** → **T (Tampering).** Injected script rewrites what other users' browsers execute, tampering with the rendered page and their session state.
5. **`missing-build-infrastructure` (juice-shop)** → **T (Tampering).** With no verified build pipeline in the model, the deployed artifact can be tampered with in the supply chain before it ever runs.

### Trust-boundary crossing

The **`Direct to App (no proxy)`** arrow (top five, risk #2) runs from **User Browser**, which lives in the **Internet** trust boundary, straight into **Juice Shop Application** in the nested **Container Network** boundary — crossing Internet → Host → Container in one hop over plaintext HTTP. It is worth an attacker's time because it carries authentication data (`session-id`, JWT) in clear text *and* bypasses the TLS-terminating reverse proxy entirely: an attacker in a network position can sniff or replay the session token and hijack the account, defeating the very control the proxy was added to provide.

## Task 2

### Baseline vs secure (2.5)

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|---:|
| critical | 0 | 0 | 0 |
| high | 0 | 0 | 0 |
| elevated | 4 | 1 | −3 |
| medium | 14 | 12 | −2 |
| low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **−5 (≈22%)** |

### Rules removed (`gone:`) and the field that removed each

- **`unencrypted-communication`** — changed both inbound links to encrypted transport: `Direct to App (no proxy)` `protocol: http → https`, and `To App` (proxy → app) `protocol: http → https`. No inbound link carries clear text anymore.
- **`missing-authentication`** — on the `To App` link (reverse-proxy → juice-shop), `authentication: none → client-certificate` (and `authorization: none → technical-user`), so the link now declares how it authenticates.
- **`unencrypted-asset`** — set `encryption: none → data-with-symmetric-shared-key` on both the `juice-shop` application asset and the `persistent-storage` datastore, i.e. encrypted at rest.

### Two rules that still fire, and why edits could not remove them

- **`cross-site-scripting` (juice-shop, still elevated).** XSS is a property of the application *code* (missing output encoding / no CSP), not of any transport, authentication or encryption field. No YAML edit to the model can change how the app renders untrusted input.
- **`server-side-request-forgery` (juice-shop → webhook, proxy → app).** The architecture still contains components that make server-side outbound/forwarded web requests. As long as that requester exists in the model, the risk stays — encrypting the link or adding auth does not remove the ability to be tricked into requesting an attacker-chosen target.

### What is left

The residual ~18 risks are almost entirely **application-layer and process/organizational**, not transport ones: XSS and CSRF in the app code, SSRF from legitimate outbound calls, missing second factor, missing hardening, missing vault, and missing build infrastructure. Encryption and authentication fields in the model close the *architecture* gaps (clear-text links, unauthenticated hops, plaintext-at-rest) but cannot touch code-level or program-level weaknesses. Closing them takes real work outside the YAML: parameterized queries and output encoding in the code, a CSRF-token scheme, an SSRF allowlist, MFA, a secrets vault, and a signed build pipeline. **`cross-site-scripting` is one that no YAML edit can close** — it is a code defect, and the model can only ever flag it.

## Bonus

Auth-flow model `labs/lab2/threagile-model-auth.yaml`, built from `-create-stub-model`: 5 technical assets (user-browser, login-endpoint, token-service, credential-store, admin-endpoint), 5 communication links, 4 data assets (user-credentials, jwt-token, **jwt-signing-key** as its own asset, admin-data). Every link declares `authentication` and `authorization`; the admin endpoint verifies the token/role via the `Verify Token` link before acting.

### Severity table

| Severity | Count |
|----------|------:|
| critical | 0 |
| high | 1 |
| elevated | 7 |
| medium | 17 |
| low | 4 |
| **Total** | **29** |

### Three risks the architecture model did not surface

| Rule (category) | Asset | STRIDE | One-sentence mitigation |
|-----------------|-------|--------|-------------------------|
| `sql-nosql-injection` | login-endpoint | **T** (Tampering) | Use parameterized queries / an ORM binding for the credential lookup so login input cannot alter the query. |
| `missing-identity-provider-isolation` | token-service | **E** (Elevation of Privilege) | Isolate the signing-key custodian in its own segment/runtime with no co-located workloads, so a neighbour compromise can't reach the key. |
| `unguarded-access-from-internet` | admin-endpoint | **S / E** (Spoofing → Elevation) | Front the endpoint with an authenticating gateway/WAF instead of letting it be reachable directly from the internet boundary. |

### What the feature-level model showed

Decomposing the login path into its own assets and links let Threagile reason about each hop's trust and data — surfacing identity-specific failure modes like the signing-key custodian needing isolation, injection at the credential lookup, and the admin route's direct internet exposure. The architecture model collapsed all of this into one `juice-shop` box, so those risks were invisible; the finer altitude is what made them appear.
