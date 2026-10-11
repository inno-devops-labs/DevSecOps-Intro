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
| **Total** | **23** |

Source: `labs/lab2/output/risks.json` (Threagile v0.9.1, baseline model).

### Top 5 risks (from `jq` output)

1. **`cross-site-scripting@juice-shop`** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity **elevated**; affecting **juice-shop**
2. **`missing-authentication@reverse-proxy>to-app@reverse-proxy@juice-shop`** — Missing Authentication on link *To App* (Reverse Proxy → Juice Shop Application); severity **elevated**; affecting **juice-shop**
3. **`unencrypted-communication@user-browser>direct-to-app-no-proxy@user-browser@juice-shop`** — Unencrypted Communication on *Direct to App (no proxy)* (User Browser → Juice Shop), transferring authentication data; severity **elevated**; affecting **user-browser**
4. **`unencrypted-communication@reverse-proxy>to-app@reverse-proxy@juice-shop`** — Unencrypted Communication on *To App* (Reverse Proxy → Juice Shop Application); severity **elevated**; affecting **reverse-proxy**
5. **`missing-identity-store@reverse-proxy`** — Missing Identity Store (example asset: Reverse Proxy); severity **medium**; affecting **reverse-proxy**

### STRIDE mapping (Lecture 2 slide 7)

- Risk 1: **T (Tampering)** — XSS lets an attacker inject script that alters what other users' browsers execute/render.
- Risk 2: **S (Spoofing)** — No authentication on the proxy→app hop means a caller on that link could impersonate a legitimate upstream client.
- Risk 3: **I (Information Disclosure)** — HTTP exposes credentials, tokens, and session IDs to any observer on the network path.
- Risk 4: **I (Information Disclosure)** — Even behind a TLS-terminating proxy, the internal HTTP segment still leaks session data to anyone on the host/container network.
- Risk 5: **S (Spoofing)** — Without a declared identity store, Threagile flags that user identity cannot be authoritatively verified end-to-end.

### Trust boundary observation

In `data-flow-diagram.png`, the arrow **Direct to App (no proxy)** crosses from **User Browser** (inside the *Internet* trust boundary) into **Juice Shop Application** (inside *Container Network*), passing through *Host*. This path is in the top-5 list as `unencrypted-communication@user-browser>direct-to-app-no-proxy`. It is attractive to an attacker because it carries **tokens-sessions** and login traffic over **plain HTTP** across a trust-boundary crossing — passive network sniffing on the lab LAN or compromised host bridge can capture session material without exploiting Juice Shop itself.

---

## Task 2: Secure Variant & Diff

Hardening applied in `labs/lab2/threagile-model-secure.yaml`:

| Change | Field |
|--------|--------|
| HTTPS browser→app | `Direct to App (no proxy)` → `protocol: https` |
| HTTPS proxy→app | `To App` → `protocol: https` |
| Encrypt data at rest | `persistent-storage` → `encryption: data-with-symmetric-shared-key` |
| Prepared statements | New `To Persistent Storage` link description declares parameterized queries; `protocol: jdbc-encrypted` |
| No plain log writes to volume | Removed `logs` from `juice-shop` `data_assets_stored`; logs no longer stored on unencrypted volume path |

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 5 | +1 |
| Medium | 14 | 13 | −1 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **23** | **0** |

### Which rules are GONE in the secure variant?

1. **`unencrypted-communication@user-browser>direct-to-app-no-proxy@user-browser@juice-shop`** — fixed by setting `protocol: https` on *Direct to App (no proxy)*.
2. **`unencrypted-communication@reverse-proxy>to-app@reverse-proxy@juice-shop`** — fixed by setting `protocol: https` on the proxy→app link.
3. **`unencrypted-asset@persistent-storage`** — fixed by declaring `encryption: data-with-symmetric-shared-key` on the storage asset.

### Which rules are STILL THERE in the secure variant?

1. **`cross-site-scripting@juice-shop`** — HTTPS and storage encryption do not sanitize user-controlled HTML/JS in reviews or other reflected/stored content; XSS requires output encoding, CSP, and input validation, not transport-layer fixes alone.

2. **`missing-authentication@reverse-proxy>to-app@reverse-proxy@juice-shop`** — Switching the link to HTTPS protects confidentiality on the wire but does not add an authentication mechanism between proxy and app; the backend still accepts any caller that can reach port 3000 on the container network.

### Honesty check

The total did **not** drop more than 50% (23 → 23, **0%** change). Encrypting links and storage removed several obvious misconfiguration findings, but declaring a new DB/storage communication link surfaced **sql-nosql-injection**, **path-traversal**, and **missing-authentication** on that path — a realistic trade-off in threat modeling. These hardening changes are **high leverage for the issues they target** (cleartext creds, data-at-rest) with modest YAML edits, yet eliminating the remaining elevated risks would require application-level controls (auth between tiers, input validation, identity store, CSP) — substantially more engineering than flipping protocol/encryption fields.

---

## Bonus Task: Auth Flow Threat Model

Model file: `labs/lab2/threagile-model-auth.yaml` (written from scratch, 7 communication links, 5 data assets).

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 16 |
| Medium | 25 |
| Low | 9 |
| **Total** | **50** |

Source: `labs/lab2/output-auth/risks.json` (Threagile v0.9.1).

### Three auth-specific risks (NOT in the baseline model's top 5)

1. **`missing-authentication-second-factor@user-browser>login-and-register@user-browser@auth-api`** — STRIDE: **S (Spoofing)** — Mitigation: Require MFA (TOTP/WebAuthn) on login and registration, especially before issuing JWTs with elevated claims.

2. **`sql-nosql-injection@auth-api@credential-store@auth-api>verify-credentials`** — STRIDE: **T (Tampering)** — Mitigation: Use parameterized queries / ORM bindings for all credential lookups so login input cannot alter the SQL query structure.

3. **`missing-vault@credential-store`** — STRIDE: **I (Information Disclosure)** — Mitigation: Store password hashes and JWT signing keys in a secrets manager (Vault/KMS) instead of plain container filesystem paths readable after container compromise.

### Reflection

The focused auth model surfaced **login-path risks** — missing MFA, SQL injection on credential verification, and missing secrets vault — that the baseline architecture model never prioritized because its top findings were generic transport issues (HTTP links, reverse proxy) and app-wide XSS. Feature-level modeling also exposed **JWT verification hops** (`missing-authentication` on auth-api→jwt-service and protected-api→jwt-service) as distinct trust gaps rather than folding them into a monolithic “Juice Shop Application” asset.
