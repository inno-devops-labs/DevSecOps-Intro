# Lab 2 — Threat Modeling with Threagile

## Task 1

### Severity table (baseline)

| Severity | Count |
|----------|------:|
| elevated | 4 |
| medium | 14 |
| low | 5 |
| **total** | **23** |

### Top five risks

| Severity | Rule ID | Asset |
|----------|---------|-------|
| elevated | cross-site-scripting | juice-shop |
| elevated | unencrypted-communication | user-browser |
| elevated | unencrypted-communication | reverse-proxy |
| elevated | missing-authentication | juice-shop |
| medium | unencrypted-asset | juice-shop |

### STRIDE mapping

1. **cross-site-scripting → XSS (Tampering / Information Disclosure)** — Injected script in the browser alters page behaviour and can steal session material.
2. **unencrypted-communication (user-browser) → Information Disclosure** — Cleartext browser→app traffic can be sniffed on the path.
3. **unencrypted-communication (reverse-proxy) → Information Disclosure** — Proxy→app HTTP exposes tokens after TLS termination.
4. **missing-authentication → Spoofing / Elevation of Privilege** — Unauthenticated callers reach application surfaces that should require identity.
5. **unencrypted-asset → Information Disclosure** — App process has no at-rest encryption, so host compromise exposes in-memory/on-disk secrets.

### Trust-boundary crossing

The **Direct to App (no proxy)** arrow from `user-browser` (Internet trust boundary) to `juice-shop` (Container Network) crosses the Internet→Host→Container boundary on cleartext `http`. That arrow appears in the top five via `unencrypted-communication` / `missing-authentication`: an attacker on the LAN path or who can reach `:3000` talks straight to the vulnerable app without the proxy’s TLS/header layer.

## Task 2

Hardening in `labs/lab2/threagile-model-secure.yaml`:
- both inbound links to the app use `protocol: https`
- reverse-proxy→app uses `authentication: client-certificate`
- `juice-shop` and `persistent-storage` use `encryption: transparent`

### Severity comparison

| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| elevated | 4 | 1 | -3 |
| medium | 14 | 12 | -2 |
| low | 5 | 5 | 0 |
| **total** | **23** | **18** | **-5 (~22%)** |

### Removed rules (`gone:`)

| Rule ID | Field change that removed it |
|---------|------------------------------|
| unencrypted-communication | `protocol: http` → `https` on browser→app and proxy→app |
| unencrypted-asset | `encryption: none` → `transparent` on juice-shop + persistent-storage |
| missing-authentication | proxy→app `authentication: none` → `client-certificate` (+ authz) |

### Still firing (examples)

1. **cross-site-scripting** — TLS and disk encryption do not stop XSS in the application code.
2. **missing-waf / missing-vault / container-baseimage-backdooring** — Architecture YAML cannot invent a WAF, secret vault, or trusted base-image pipeline; those need real components.

### What is left

Roughly a fifth of findings disappeared; the remainder are app-logic and process gaps (XSS, CSRF, SSRF, missing WAF/2FA/build infra). Closing them needs code fixes, a WAF, vaulting secrets, and supply-chain controls — **not** more YAML toggles. One risk no YAML edit can close: **cross-site-scripting** in Juice Shop itself (deliberately vulnerable handlers).

## Bonus

Auth-flow model: `labs/lab2/threagile-model-auth.yaml` (from stub; ≥5 tech assets, ≥5 links, 4 data assets including `jwt-signing-key`; every link has authentication + authorization; admin call uses token + `enduser-identity-propagation`).

### Severity table (auth model)

| Severity | Count |
|----------|------:|
| high | 1 |
| elevated | 6 |
| medium | 17 |
| low | 4 |
| **total** | **28** |

### Risks the architecture model did not surface

| Rule ID | STRIDE | Mitigation |
|---------|--------|------------|
| sql-nosql-injection | Tampering | Parameterize login queries / ORM binding; never concatenate email into SQL. |
| missing-identity-propagation | Spoofing | Propagate verified subject claims into admin handlers; reject missing identity. |
| unguarded-access-from-internet | Elevation of Privilege | Put admin behind network policy / VPN and enforce authz at the edge. |

Feature-level modeling showed credential-store and JWT-key paths that the coarse architecture model treated as one “app” blob. That is why injection on login and identity-provider isolation appear only here.
