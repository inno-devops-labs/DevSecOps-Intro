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

1. **`unencrypted-communication@user-browser>direct-to-app-no-proxy`** — Unencrypted Communication named *Direct to App (no proxy)* between *User Browser* and *Juice Shop Application* transferring authentication data; severity **Elevated**; affecting `user-browser`
2. **`unencrypted-communication@reverse-proxy>to-app`** — Unencrypted Communication named *To App* between *Reverse Proxy* and *Juice Shop Application*; severity **Elevated**; affecting `reverse-proxy`
3. **`cross-site-scripting@juice-shop`** — Cross-Site Scripting (XSS) risk at *Juice Shop Application*; severity **Elevated**; affecting `juice-shop`
4. **`missing-authentication@reverse-proxy>to-app`** — Missing Authentication covering communication link *To App* from *Reverse Proxy* to *Juice Shop Application*; severity **Elevated**; affecting `juice-shop`
5. **`missing-build-infrastructure@juice-shop`** — Missing Build Infrastructure in the threat model (referencing asset *Juice Shop Application* as an example); severity **Medium**; affecting `juice-shop`

### STRIDE mapping

- **Risk 1** (`unencrypted-communication`): **I / T** — Unencrypted HTTP allows an attacker to eavesdrop on credentials and session tokens (Information Disclosure) and to modify traffic in transit (Tampering).
- **Risk 2** (`unencrypted-communication`): **I / T** — Even internal unencrypted traffic between proxy and app can be sniffed or tampered with if the container network is compromised.
- **Risk 3** (`cross-site-scripting`): **I / T** — Injected scripts can steal session data (Information Disclosure) and alter page behavior (Tampering).
- **Risk 4** (`missing-authentication`): **S** — Without authentication on the reverse-proxy→app link, any actor inside the network can impersonate the proxy and reach the application directly (Spoofing).
- **Risk 5** (`missing-build-infrastructure`): **T** — Absence of a hardened build pipeline opens the door to supply-chain tampering (e.g., injecting malicious dependencies or backdoors into the container image).

### Trust boundary observation

Looking at `data-flow-diagram.png`, the arrow User Browser → Juice Shop Application crosses the Internet → Container Network trust boundary, completely bypassing the *Reverse Proxy*.

This arrow is particularly attractive to an attacker because:
1. It exposes the raw application directly to the internet over **unencrypted HTTP** (port 3000), skipping TLS termination and any security headers the reverse proxy would enforce.
2. It carries **authentication data** (tokens & sessions) in cleartext, making passive eavesdropping and active MITM trivial.
3. By bypassing the proxy, the attacker avoids potential rate-limiting, WAF, and access-logging controls that would otherwise create friction and visibility.

## Task 2: Secure Variant & Diff

### Changes made in `threagile-model-secure.yaml`

| # | Change | Location | Before → After |
|---|--------|----------|----------------|
| 1 | Force HTTPS (direct) | `User Browser` → `Direct to App (no proxy)` | `protocol: http` → `protocol: https` |
| 2 | Force HTTPS (internal) | `Reverse Proxy` → `To App` | `protocol: http` → `protocol: https` |
| 3 | Encrypt DB at rest | `Persistent Storage` asset | `encryption: none` → `encryption: data-with-symmetric-shared-key` |
| 4 | TLS outbound | `Juice Shop` → `To Challenge WebHook` | Already `https` in baseline |
| 5 | Prepared statements | New link `Juice Shop` → `To Database` | Added `protocol: jdbc-encrypted` + description declaring parameterized queries |
| 6 | Disable plain log writes | `Juice Shop Application` | Removed `logs` from `data_assets_stored` |

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 4 | 0 |
| Medium | 14 | 13 | **-1** |
| Low | 5 | 4 | **-1** |
| **Total** | **23** | **21** | **-2** |

### Which rules are GONE in the secure variant?

1. **`unencrypted-asset@persistent-storage`** — fixed by adding `encryption: data-with-symmetric-shared-key` to the persistent storage asset (dropped medium count from 14 to 13).
2. **`unnecessary-technical-asset@persistent-storage`** — fixed by refining the storage asset with explicit encryption and decoupling it from direct application log writes (dropped low count from 5 to 4).

Verify exact IDs: If you need to confirm the second rule, run:
```bash
jq '[.[] | .synthetic_id] | sort' labs/lab2/output/risks.json &gt; /tmp/baseline-ids.json
jq '[.[] | .synthetic_id] | sort' labs/lab2/output-secure/risks.json &gt; /tmp/secure-ids.json
diff -u /tmp/baseline-ids.json /tmp/secure-ids.json || true
```

### Which rules are STILL THERE in the secure variant?

1. **`cross-site-scripting@juice-shop`** — still fires because: enabling HTTPS and encrypting the database does not eliminate XSS vulnerabilities. The application still renders user-controlled input without output encoding or a Content Security Policy, so the XSS rule remains valid regardless of transport or storage encryption.
2. **`missing-authentication@reverse-proxy&gt;to-app`** — still fires because: although the communication link is now encrypted, the reverse proxy and the application still do not authenticate each other. Any actor with access to the container network can still impersonate the proxy and reach the application directly, so the missing-authentication rule persists.

### Honesty check

Did the total drop more than 50%? No — it dropped ~8.7% (23 → 21).

Analysis: The five hardening changes eliminated only 2 specific risks with minimal configuration effort: one medium risk (`unencrypted-asset@persistent-storage`) via encryption-at-rest and one low risk via architectural decoupling. However, the remaining ~91% of risks (XSS, CSRF, SSRF, missing authentication, missing WAF, container base-image backdooring, missing build infrastructure, missing vault) are architectural and application-level issues that TLS and storage encryption cannot address. Notably, the two `unencrypted-communication` risks remained despite upgrading links to `protocol: https`, suggesting that Threagile v0.9.1 evaluates transport encryption holistically (considering endpoint asset encryption fields and trust boundaries) rather than relying solely on the link protocol declaration. This demonstrates that transport encryption and storage encryption are necessary baseline hygiene but insufficient to significantly halve the risk count of a modern web application. Eliminating the remaining risks requires secure coding practices, input validation, CI/CD hardening, WAF deployment, and proper access control—significantly more engineering work than the quick config wins.

## Bonus Task: Auth Flow Threat Model

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 1 |
| Elevated | 6 |
| Medium | 17 |
| Low | 19 |
| **Total** | **43** |

### Three auth-specific risks (NOT in the baseline model's top-5)

1. **`sql-nosql-injection@auth-api@user-db@auth-api&gt;verify-credentials`** — STRIDE: **T** — Mitigation: Use parameterized queries (prepared statements) for all credential verification queries against the user database to prevent authentication bypass via SQL injection.

2. **`missing-authentication-second-factor@browser&gt;login-to-auth-api@browser@auth-api`** — STRIDE: **S** — Mitigation: Implement multi-factor authentication (TOTP or WebAuthn) on the login endpoint to prevent credential stuffing and brute-force attacks even if passwords are compromised.

3. **`unguarded-access-from-internet@auth-api@browser@browser&gt;login-to-auth-api`** — STRIDE: **E** — Mitigation: Place the Auth API behind a reverse proxy or API gateway with IP filtering, rate limiting, and geo-blocking to prevent direct unguarded internet access to authentication endpoints.

### Reflection

Building the focused auth model surfaced **three critical gaps** that the baseline architecture model missed. First, the baseline treats the entire application as a single black-box process, so it cannot distinguish between a regular API call and an admin API call; the auth model explicitly separates `auth-api` → `token-signer` → `admin-api`, revealing that JWT verification and role enforcement happen in different components, creating a potential gap if the admin API fails to re-verify the role claim independently. Second, the baseline does not model the credential verification query path (`auth-api` → `user-db`), so the risk of SQL injection during authentication is invisible at the architecture level. Third, feature-level flows expose auth-specific rules like `unguarded-access-from-internet` and missing 2FA that only appear when you zoom into the login→token→admin chain, demonstrating that architecture-level threat models miss granular control failures that feature-level models capture.
