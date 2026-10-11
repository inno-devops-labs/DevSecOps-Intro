# Lab 2 - Submission

## Task 1: Baseline Threat Model

### Threagile run

Command:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model.yaml \
  -output /app/work/output \
  -generate-risks-excel=false \
  -generate-tags-excel=false
```

The Excel exports were disabled because the pinned container generated `the sheet name length exceeds the 31 characters limit`. The required `report.pdf`, diagrams, `risks.json`, `stats.json`, and `technical-assets.json` were generated successfully.

Generated files:

```text
data-asset-diagram.png
data-flow-diagram.png
report.pdf
risks.json
stats.json
technical-assets.json
```

### Risk count by severity

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | 23 |

### Top 5 risks

1. **cross-site-scripting** - Cross-Site Scripting (XSS) risk at Juice Shop Application; severity **elevated**; affecting `juice-shop`.
2. **unencrypted-communication** - Direct to App (no proxy) from User Browser to Juice Shop Application transfers authentication data without encryption; severity **elevated**; link `user-browser>direct-to-app-no-proxy`.
3. **unencrypted-communication** - Reverse Proxy to Juice Shop Application uses unencrypted communication; severity **elevated**; link `reverse-proxy>to-app`.
4. **missing-authentication** - Reverse Proxy to Juice Shop Application has no authentication on the internal app link; severity **elevated**; link `reverse-proxy>to-app`.
5. **missing-authentication-second-factor** - Direct browser-to-app login/session flow has no second factor; severity **medium**; link `user-browser>direct-to-app-no-proxy`.

### STRIDE mapping

- Risk 1: **T/I/E** - XSS can tamper with page behavior, disclose token/session data, and sometimes execute actions as the victim.
- Risk 2: **I/S** - Unencrypted browser-to-app traffic can disclose tokens or credentials and let an attacker impersonate the user.
- Risk 3: **I/T** - Unencrypted proxy-to-app traffic can expose or modify forwarded session traffic inside the host/container boundary.
- Risk 4: **S/E** - Missing authentication on the proxy-to-app link means a component that can reach the app may spoof trusted proxy traffic or bypass intended access paths.
- Risk 5: **S/E** - Missing 2FA leaves authentication dependent on one factor, increasing account takeover and privilege escalation risk after password compromise.

### Trust boundary observation

The `Direct to App (no proxy)` arrow from `User Browser` to `Juice Shop Application` crosses from the untrusted Internet/browser side into the containerized application. It is attractive because it carries authentication/session data and reaches the app without the reverse proxy controls described in the model, so it combines trust-boundary crossing, public reachability, and credential-bearing traffic.

## Task 2: Secure Variant & Diff

### Secure-variant changes

I created `labs/lab2/threagile-model-secure.yaml` and made these hardening changes:

- Changed `User Browser -> Direct to App (no proxy)` from `http` to `https`.
- Changed `Reverse Proxy -> Juice Shop Application` from `http` to `https`.
- Added `session-id` authentication and `enduser-identity-propagation` authorization on the proxy-to-app link.
- Set `Persistent Storage` encryption to `data-with-symmetric-shared-key`.
- Set `Juice Shop Application` encryption to `transparent`.
- Added `Juice Shop Application -> Persistent Storage` as `jdbc-encrypted` with description explicitly stating parameterized queries / prepared statements and sanitized log writes.
- Kept the outbound `To Challenge WebHook` integration on `https`.

Command:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-secure.yaml \
  -output /app/work/output-secure \
  -generate-risks-excel=false \
  -generate-tags-excel=false
```

### Risk count comparison

| Severity | Baseline | Secure | Delta |
|----------|---------:|-------:|------:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 3 | -1 |
| Medium | 14 | 12 | -2 |
| Low | 5 | 4 | -1 |
| **Total** | 23 | 19 | -4 |

Diff output:

```diff
@@
   {
     "severity": "elevated",
-    "count": 4
+    "count": 3
   },
   {
     "severity": "medium",
-    "count": 14
+    "count": 12
   },
   {
     "severity": "low",
-    "count": 5
+    "count": 4
   }
```

### Which rules are gone in the secure variant?

1. `unencrypted-communication` - fixed by changing browser-to-app and proxy-to-app traffic to `https`.
2. `missing-authentication` - fixed by adding session-based authentication and propagated end-user authorization on the proxy-to-app link.
3. `unencrypted-asset` - fixed by encrypting `Persistent Storage` and marking the application asset as transparently encrypted in the hardened model.

### Which rules are still there in the secure variant?

1. `cross-site-scripting` still fires because transport encryption and storage encryption do not remove unsafe browser-executed input/output handling. Mitigation would require output encoding, CSP, input validation, and framework-level XSS controls.

2. `missing-authentication-second-factor` still fires because the secure variant kept the same user authentication model and did not introduce MFA. HTTPS protects the channel, but it does not add a second identity proof if a password or token is stolen.

3. `server-side-request-forgery` still fires on the outbound webhook path because the app can still make server-side requests to an external endpoint. HTTPS protects the channel but does not prevent abusing the server as a request origin; allowlists, egress policy, and URL validation are needed.

### Honesty check

The total did not drop by more than 50%; it dropped from 23 to 19, about 17%. That is still useful because a handful of low-cost model changes removed the direct unencrypted and missing-authentication findings, but the remaining risks require deeper application design and control changes, not just protocol/encryption fields.

The secure variant also introduced `sql-nosql-injection` and `path-traversal` findings because I made the database/storage communication explicit. That is a useful modeling side effect: adding a more honest data-store link exposes risks that the baseline model hid by omitting the app-to-storage flow.

## Bonus Task: Auth Flow Threat Model

### Model summary

I created `labs/lab2/threagile-model-auth.yaml` from scratch as a focused auth model. It includes five technical assets: Browser, Auth API Endpoint, Token Signing and Verification, User DB Credential Store, and Admin Endpoint. It includes five data assets: Credentials, JWT Token, User Session State, Admin Operation Requests, and JWT Signing Key. It has seven communication links covering login/register, JWT issuance, protected API use, JWT verification, admin access, and credential/role lookup.

Command:

```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-auth.yaml \
  -output /app/work/output-auth \
  -generate-risks-excel=false \
  -generate-tags-excel=false
```

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 2 |
| Elevated | 6 |
| Medium | 15 |
| Low | 5 |
| **Total** | 28 |

### Three auth-specific risks

1. **sql-nosql-injection** - STRIDE: **T/E** - Threagile flags SQL/NoSQL injection on `Auth API Endpoint -> User DB Credential Store` and `Admin Endpoint -> User DB Credential Store`. Mitigation: use parameterized queries, strict ORM query construction, allowlisted role lookup logic, and tests around login/admin query paths.

2. **unguarded-access-from-internet** - STRIDE: **E/S** - The model exposes Auth API and Admin Endpoint flows from the browser boundary, including the admin JWT path. Mitigation: keep admin APIs behind explicit server-side role checks, rate limits, monitoring, and where possible network or admin-only access controls.

3. **missing-vault** - STRIDE: **I/S** - The auth model contains a JWT signing key, but no vault/secret-store component. Mitigation: store signing keys in a vault/KMS or equivalent secret manager, rotate them, and never keep them in source code, logs, or ordinary database tables.

### Reflection

The focused auth model surfaced risks that the baseline architecture model did not prioritize, especially injection in credential/role lookup and the need for explicit secret storage around JWT signing keys. The broader model is useful for trust boundaries and transport/security posture, but the feature-level model makes auth-specific abuse paths much more visible.

## Submission Checklist

- [x] Task 1 - Baseline risk table + top-5 with STRIDE mapping
- [x] Task 2 - Secure variant + risk diff table
- [x] Bonus - Auth-flow model + 3 auth-specific risks
