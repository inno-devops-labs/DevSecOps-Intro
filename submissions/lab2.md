# Lab 2 — Submission
---

## Task 1: Baseline Threat Model

### Risk count by severity

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | 23 |

### Top 5 risks (from `labs/lab2/output/risks.json`)

1. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at Juice Shop Application; severity **elevated**; affecting **juice-shop**
2. **unencrypted-communication** — Unencrypted Communication on link **Direct to App (no proxy)** between User Browser and Juice Shop Application (auth data: credentials, tokens, session-id); severity **elevated**; affecting **user-browser**
3. **unencrypted-communication** — Unencrypted Communication on link **To App** between Reverse Proxy and Juice Shop Application; severity **elevated**; affecting **reverse-proxy**
4. **missing-authentication** — Missing Authentication on link **To App** from Reverse Proxy to Juice Shop Application; severity **elevated**; affecting **juice-shop**
5. **unnecessary-technical-asset** — Unnecessary Technical Asset named Persistent Storage; severity **low**; affecting **persistent-storage**

### STRIDE mapping (Lecture 2 slide 7)

- Risk 1: **T** (Tampering) — XSS lets attackers inject/modify js-scripts executed in victims' browsers.
- Risk 2: **I** (Information Disclosure) — HTTP exposes session tokens and credentials to on-path eavesdropping.
- Risk 3: **I** (Information Disclosure) — cleartext proxy→app hop allows sniffing or modifying traffic inside the host boundary.
- Risk 4: **S** (Spoofing) — proxy→app link has no authentication; a rogue internal caller could impersonate trusted traffic.
- Risk 5: **I** (Information Disclosure) — unnecessary storage expands attack surface and data exposure scope without clear business need.

### Trust boundary observation

On `data-flow-diagram.png`, the arrow **User Browser → Juice Shop (Direct to App, HTTP/HTTPS)** crosses the **Internet → Host** trust boundary.

This link is attractive because it carries **session tokens and catalog data** from an untrusted client network into the application tier. In the baseline model the direct path uses **plain HTTP**, so an on-path attacker can read or modify traffic (STRIDE **I** and **T**) without touching the container.

---

## Task 2: Secure Variant & Diff

Secure model file: `labs/lab2/threagile-model-secure.yaml`

**Hardening applied (5/5):**

**What we changed in the secure YAML:**

1. **HTTPS for users** — browser now talks to Juice Shop over HTTPS instead of HTTP.
2. **Encrypted database storage** — persistent storage uses encryption at rest.
3. **HTTPS for WebHook** — outbound calls to the external WebHook stay on HTTPS.
4. **Prepared statements** — added a DB link with a note that the app uses parameterized queries.
5. **No plain log writes** — removed logs from plain storage in the model.

**Generate secure report:**

```bash
docker run --rm \
  -v "$(pwd)/labs/lab2":/app/work \
  threagile/threagile:0.9.1 \
  -model /app/work/threagile-model-secure.yaml \
  -output /app/work/output-secure
```

### Risk count comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 1 | -3 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 19 | -4 |


### Top 5 comparison (baseline vs secure)

**Baseline** had 4 elevated + 1 low in top 5: XSS, two unencrypted links, missing authentication on proxy→app, unnecessary storage.

**Secure** has 1 elevated + 4 low in top 5: only XSS stays elevated; the three transport/auth elevated findings are gone. New low findings appear for unnecessary data transfer of tokens (browser↔app and browser↔proxy) and unnecessary user-browser asset.

So diff is 4 risks

### Rules GONE in the secure variant

1. **unencrypted-communication** (on "Direct to App (no proxy)", User Browser → Juice Shop) — fixed by switching that link from `http` to `https`.
2. **unencrypted-communication** (on "To App", Reverse Proxy → Juice Shop) — no longer in top risks after hardening; elevated count dropped from 4 to 1.
3. **missing-authentication** (on "To App", Reverse Proxy → Juice Shop) — no longer in top 5; removed together with the other two elevated transport/auth findings.

That's rules removed all three eliminated elevated risks besides XSS (one missing-authentication + two unencrypted-communication).

### Rules STILL firing in the secure variant (and why)

1. **cross-site-scripting** — XSS is an application-code flaw (unescaped output), not a transport setting. No architecture YAML field removes it; it needs code fixes (use secure template rendering, secure js-sinks or use sanitizer such as dompurify).
2. **unnecessary-data-transfer** (Tokens & Sessions at User Browser) — HTTPS protects the channel but tokens still flow browser↔app and browser↔proxy; Threagile flags the transfer itself as unnecessary exposure surface.
3. **unnecessary-technical-asset** (Persistent Storage, User Browser) — declaring encryption and HTTPS does not remove assets from the model; Threagile still questions whether every component is strictly required.

### Honesty check

Did the total drop more than 50%? **No** (23 → 19, about 17% reduction).

We removed the cheap wins (HTTPS on direct user traffic, encrypted storage, DB link hardening), but XSS and several low-tier structural findings remain. Getting to near-zero would need code changes, tighter data-flow design, and more than five YAML field edits.

---

## Bonus Task: Auth Flow Threat Model

- Model: `labs/lab2/threagile-model-auth.yaml`
- Output: `labs/lab2/output-auth/`

### Risk count

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 6 |
| Medium | 22 |
| Low | 11 |
| **Total** | 39 |

### Three auth-specific risks (NOT in baseline top 5)

Baseline top 5 covered generic XSS, unencrypted browser/proxy links, missing proxy auth, and unnecessary storage — not login, JWT, or admin-route specifics.

1. **sql-nosql-injection** — STRIDE: **T** (Tampering) — Mitigation: use parameterized queries on the **Verify Credentials** link to User DB; never concatenate user input into SQL at login time.

2. **missing-authentication-second-factor** — STRIDE: **S** (Spoofing) — Mitigation: require 2FA (TOTP or WebAuthn) on **Login and Register** so a stolen password alone cannot create or hijack a session.

3. **server-side-request-forgery** — STRIDE: **E** (Elevation) — Mitigation: allowlist internal targets on **Request JWT** and **Forward to Admin Check**; Auth API must not call arbitrary internal URLs when reaching Token Signer or Admin API.

### Reflection

The auth-focused model surfaced login-time injection, missing 2FA on credential flows, and SSRF-style server-side hops between Auth API, Token Signer, and Admin API. The baseline architecture model only showed generic Juice Shop risks and missed this login → JWT → admin chain. Feature-level modeling is better for Spoofing and Elevation in auth flows.
