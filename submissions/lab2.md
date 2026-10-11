# Lab 2: Threat Modeling with Threagile

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

1. **missing-authentication** — Missing Authentication covering communication link `To App` from `Reverse Proxy` to `Juice Shop Application`; severity Elevated; affecting `juice-shop`.
2. **unencrypted-communication** — Unencrypted Communication named `Direct to App (no proxy)` between `User Browser` and `Juice Shop Application`, transferring authentication data; severity Elevated; affecting `user-browser`.
3. **unencrypted-communication** — Unencrypted Communication named `To App` between `Reverse Proxy` and `Juice Shop Application`; severity Elevated; affecting `reverse-proxy`.
4. **cross-site-scripting** — Cross-Site Scripting risk at `Juice Shop Application`; severity Elevated; affecting `juice-shop`.
5. **missing-identity-store** — Missing Identity Store in the threat model, referencing `Reverse Proxy`; severity Medium; affecting `reverse-proxy`.

### STRIDE mapping

- Risk 1: **S/E** — Missing backend authentication allows a caller to spoof trusted proxy traffic and potentially reach app functionality without the intended trust proof.
- Risk 2: **I/S** — Plain HTTP can expose session tokens and let an attacker reuse them to impersonate a user.
- Risk 3: **I/T** — Plain proxy-to-app traffic can be observed or modified inside the host/container path.
- Risk 4: **T/E** — XSS tampers with browser-executed content and can escalate into session theft or unauthorized actions.
- Risk 5: **S/R** — Without a modeled identity store, the architecture cannot clearly prove who authenticated or support a reliable audit trail.

### Trust boundary observation

The `User Browser -> Direct to App (no proxy) -> Juice Shop Application` arrow crosses from the untrusted Internet boundary into the container-hosted application. It is attractive because it carries authentication/session data directly to the app; if that path stays HTTP, an attacker can target token disclosure or tampering before later controls see the request.

## Task 2: Secure Variant & Diff

### Hardening changes made

- Changed direct browser-to-app traffic from `http` to `https`.
- Changed reverse-proxy-to-app traffic from `http`/unauthenticated to `https` with `client-certificate` authentication and `technical-user` authorization.
- Kept outbound WebHook traffic on `https` and documented it as an HTTPS POST.
- Added an explicit app-to-storage database link using `sql-access-protocol-encrypted`.
- Marked persistent storage as `data-with-symmetric-shared-key` encrypted.
- Documented prepared statements / parameterized SQLite queries and sanitized log writes to avoid plaintext secrets in logs.
- Clarified that the browser processes/stores session and product data, which removes model-noise risks about unnecessary transfers.

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 2 | -2 |
| Medium | 14 | 14 | 0 |
| Low | 5 | 1 | -4 |
| **Total** | **23** | **17** | **-6** |

### Which rules are GONE in the secure variant?

1. **missing-authentication** — fixed by adding authenticated backend communication from reverse proxy to app (`client-certificate`, `technical-user`).
2. **unencrypted-communication** — fixed by changing direct and proxy app traffic to HTTPS and using encrypted SQL access for storage.
3. **unnecessary-data-transfer** — fixed by declaring that the browser actually processes/stores session and catalog data it receives.
4. **unnecessary-technical-asset** — fixed by the same browser data-asset clarification, so the browser is no longer modeled as an unused asset.

### Which rules are STILL THERE in the secure variant?

1. **cross-site-scripting** — HTTPS and storage encryption do not remove input/output encoding risk in a web application. Juice Shop still accepts user-controlled data and needs contextual output encoding, CSP, and server-side validation.
2. **sql-nosql-injection** — The secure model documents parameterized queries, but Threagile still flags database access as a risk category because the app talks to a database over a SQL protocol. In practice, this would be tracked as mitigated only after code review/SAST confirms parameterized queries everywhere.
3. **missing-vault** — Encrypting storage does not create a dedicated secret-management component. JWT keys, database credentials, and integration secrets would still need a vault or equivalent secret store.

### Honesty check

No, the total did not drop by more than 50%; it dropped from 23 to 17 risks, about 26%. These hardening changes are high value because they remove avoidable plaintext and authentication gaps, but the remaining risks are deeper application and platform concerns that require code fixes, WAF/CSRF defenses, secret management, CI/CD modeling, and runtime hardening.

## Bonus Task: Auth Flow Threat Model

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 5 |
| Medium | 19 |
| Low | 4 |
| **Total** | **28** |

### Three auth-specific risks not in the baseline top 5

1. **sql-nosql-injection** — STRIDE: **T/E** — The `Auth API -> Credential Store` query path can be abused to tamper with credential lookup logic or bypass authentication. Mitigation: enforce parameterized queries for every auth lookup and add SAST/DAST tests specifically around login and registration.
2. **unguarded-access-from-internet** — STRIDE: **D/E** — The focused model shows the Auth API and Admin API reachable directly from the browser without a modeled guarding layer. Mitigation: place a reverse proxy/WAF/API gateway in front, rate-limit auth routes, and require explicit admin authorization checks before privileged operations.
3. **missing-authentication-second-factor** — STRIDE: **S/E** — JWT-only access to admin routes means stolen credentials or tokens can become enough for privileged access. Mitigation: require MFA or step-up authentication for admin operations and bind admin tokens to short lifetimes.

### Reflection

The focused auth model surfaced feature-level issues that the baseline architecture view diluted, especially database-backed credential lookup, admin JWT usage, and missing 2FA on privileged flows. The baseline is good at showing insecure transport and major architectural gaps; the auth model is better at showing how a valid-looking token can become the center of spoofing and elevation-of-privilege attacks.
