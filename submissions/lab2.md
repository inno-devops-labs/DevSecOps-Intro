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

### Top 5 risks

1. **unencrypted-communication** — Proxy→App over HTTP; severity Elevated; affecting `reverse-proxy`
2. **unencrypted-communication** — Browser→App direct over HTTP, transfers auth data; severity Elevated; affecting `user-browser`
3. **cross-site-scripting** — XSS risk at Juice Shop Application; severity Elevated; affecting `juice-shop`
4. **missing-authentication** — no auth on Proxy→App link; severity Elevated; affecting `juice-shop`
5. **unnecessary-technical-asset** — Persistent Storage flagged as unnecessary; severity Low; affecting `persistent-storage`

### STRIDE mapping

- Risk 1 (`unencrypted-communication`, Proxy→App): **T** — plaintext internal traffic allows interception and modification of data in transit.
- Risk 2 (`unencrypted-communication`, Browser→App): **I** — session tokens sent over HTTP are exposed to passive eavesdropping.
- Risk 3 (`cross-site-scripting`): **T** — injected scripts tamper with page content and can steal session tokens from other users.
- Risk 4 (`missing-authentication`): **S** — any process with network access to the internal link can impersonate the reverse proxy.
- Risk 5 (`unnecessary-technical-asset`): **E** — unencrypted storage holding user accounts and orders increases blast radius on host compromise.

### Trust boundary observation

The **"Direct to App (no proxy)"** arrow in `data-flow-diagram.png` crosses from the **Internet** boundary (User Browser) straight into the **Container Network** (Juice Shop), bypassing the Host boundary. It carries session tokens over plain HTTP with no TLS, WAF, or rate limiting — making it the most attractive target for credential interception and session hijacking.

---

## Task 2: Secure Variant & Diff

### Changes made to `threagile-model-secure.yaml`

| # | Change | Location | Old value | New value |
|---|--------|----------|-----------|-----------|
| 1 | Force HTTPS on direct browser→app link | `User Browser` → `Direct to App (no proxy)` | `protocol: http` | `protocol: https` |
| 2 | Force HTTPS on proxy→app internal link | `Reverse Proxy` → `To App` | `protocol: http` | `protocol: https` |
| 3 | Add authentication on proxy→app link | `Reverse Proxy` → `To App` | `authentication: none` | `authentication: token` |
| 4 | Add authorization on proxy→app link | `Reverse Proxy` → `To App` | `authorization: none` | `authorization: technical-user` |
| 5 | Encrypt Juice Shop application asset | `Juice Shop Application` | `encryption: none` | `encryption: data-with-symmetric-shared-key` |
| 6 | Encrypt persistent storage asset | `Persistent Storage` | `encryption: none` | `encryption: data-with-symmetric-shared-key` |

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | -3 |
| Medium | 14 | 12 | -2 |
| Low | 5 | 5 | 0 |
| **Total** | **23** | **18** | **-5** |

### Which rules are GONE in the secure variant?

1. `unencrypted-communication` (Proxy→App) — fixed by `protocol: https` on the internal link
2. `unencrypted-communication` (Browser→App) — fixed by `protocol: https` on the direct link
3. `missing-authentication` (Proxy→App) — fixed by `authentication: token` + `authorization: technical-user`
4. `unencrypted-asset` (Juice Shop) — fixed by `encryption: data-with-symmetric-shared-key`
5. `unencrypted-asset` (Persistent Storage) — fixed by `encryption: data-with-symmetric-shared-key`

### Which rules are STILL THERE in the secure variant?

1. **`cross-site-scripting`** — XSS is a code-level issue in how the app handles user input. Transport encryption and authentication headers have no effect on it; fixing it requires input sanitization and a Content Security Policy.

2. **`missing-authentication-second-factor`** — The model still describes single-factor auth. MFA requires application-level changes that cannot be expressed in Threagile YAML fields.

### Honesty check

Total dropped by 5 risks (≈22%), well under 50%. The fixed risks were all cheap infrastructure wins (TLS, encryption at rest). The remaining 18 are application-layer issues — XSS, CSRF, missing MFA, SSRF, container hardening — that require code changes and additional controls. Easy wins are worth doing first, but they leave the majority of the attack surface untouched.

---

## Bonus Task: Auth Flow Threat Model

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 12 |
| Medium | 22 |
| Low | 6 |
| **Total** | **41** |

### Three auth-specific risks NOT in the baseline model's top 5

1. **`sql-nosql-injection`** — STRIDE: **T** (Tampering)
   High-severity SQL injection on the `Credential Lookup` link (Auth API → Credential Store). The baseline never models this link explicitly, so the rule never fires. Mitigation: parameterized queries for all credential lookups.

2. **`unguarded-access-from-internet`** — STRIDE: **E** (Elevation of Privilege)
   Auth API and Admin Endpoint are directly reachable from the Internet with no WAF or rate limiting. The baseline hides this behind an optional proxy. Mitigation: WAF or API gateway in front of auth endpoints; per-IP rate limiting on login.

3. **`missing-vault`** — STRIDE: **I** (Information Disclosure)
   The Token Signer stores the JWT signing key with no secrets manager declared. This fires because the auth model explicitly declares `jwt-signing-key` as a `strictly-confidential` asset — detail absent from the baseline. Mitigation: store the signing key in a secrets manager; inject at runtime via environment variable.

### Reflection

The focused auth model surfaced SQL injection, direct internet exposure, and missing secrets management — none of which appear in the baseline top 5. The baseline treats all of Juice Shop as one "web-server" process, so Threagile cannot reason about internal auth data flows. Modeling each link explicitly (Auth API → Credential Store, Auth API → Token Signer) is where the highest-severity auth risks emerge.
