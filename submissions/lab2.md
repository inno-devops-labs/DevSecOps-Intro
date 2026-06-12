## Task 1: Baseline Threat Model

### Risk count by severity

| Severity  | Count |
| --------- | ----: |
| Critical  |   <n> |
| High      |   <n> |
| Elevated  |   <n> |
| Medium    |   <n> |
| Low       |   <n> |
| **Total** |   <n> |

### Top 5 risks (paste from `jq` output)

```json
[
  {
    "severity": "elevated",
    "category": "missing-authentication",
    "title": "<b>Missing Authentication</b> covering communication link <b>To App</b> from <b>Reverse Proxy</b> to <b>Juice Shop Application</b>",
    "technical_asset": "juice-shop"
  },
  {
    "severity": "elevated",
    "category": "cross-site-scripting",
    "title": "<b>Cross-Site Scripting (XSS)</b> risk at <b>Juice Shop Application</b>",
    "technical_asset": "juice-shop"
  },
  {
    "severity": "elevated",
    "category": "unencrypted-communication",
    "title": "<b>Unencrypted Communication</b> named <b>Direct to App (no proxy)</b> between <b>User Browser</b> and <b>Juice Shop Application</b> transferring authentication data (like credentials, token, session-id, etc.)",
    "technical_asset": "user-browser"
  },
  {
    "severity": "elevated",
    "category": "unencrypted-communication",
    "title": "<b>Unencrypted Communication</b> named <b>To App</b> between <b>Reverse Proxy</b> and <b>Juice Shop Application</b>",
    "technical_asset": "reverse-proxy"
  },
  {
    "severity": "low",
    "category": "unnecessary-technical-asset",
    "title": "<b>Unnecessary Technical Asset</b> named <b>Persistent Storage</b>",
    "technical_asset": "persistent-storage"
  }
]
```

### STRIDE mapping (Lecture 2 slide 7)

For each top-5 risk, name the STRIDE letter(s) it primarily violates:

- Risk 1: **Spoofing (S)** — Allows attackers to bypass identity checks and impersonate legitimate users or services.
- Risk 2: **Tampering (T)** — Enables injection of malicious scripts to alter web page content and execution flow.
- Risk 3: **Information Disclosure (I)** — Cleartext transmission allows eavesdroppers to intercept sensitive credentials and tokens.
- Risk 4: **Information Disclosure (I)** — Unencrypted internal traffic allows network attackers to intercept sensitive data in transit.
- Risk 5: **Denial of Service (D)** — Unnecessary assets expand the attack surface, providing extra targets for system disruption.

### Trust boundary observation

An arrow from user browser to the Juice shop application crosses a trust boundary. It is labeled http, which mean, anyone can intercept unencrypted data. Also traffic moves from the completely untrusted Internet zone directly into the protected Container Network, giving external attackers a direct line to the most sensitive application layer. This is highlighted in Risk 3.

## Task 2: Secure Variant & Diff

### Risk count comparison

| Severity  | Baseline | Secure |   Δ |
| --------- | -------: | -----: | --: |
| Critical  |        0 |      0 |   0 |
| High      |        0 |      0 |   0 |
| Elevated  |        4 |      2 |   2 |
| Medium    |       14 |     12 |   2 |
| Low       |        5 |      5 |   0 |
| **Total** |       23 |     19 |   4 |

### Which rules are GONE in the secure variant?

List 3 rule IDs that fired in baseline but not in secure-variant:

1. `unencrypted-asset` — fixed by setting `encryption: data-with-symmetric-shared-key` on Persistent Storage (eliminated both instances)
2. `missing-authentication` — fixed by adding `authentication: token` to the Reverse Proxy -> App communication link (eliminated the single instance)
3. `unencrypted-communication` — partially fixed by changing `protocol: http` to `protocol: https` on the "Direct to App" link (reduced from 2 instances to 1; the remaining instance is the internal Reverse Proxy -> App link)

### Which rules are STILL THERE in the secure variant?

`unencrypted-communication` — The Reverse Proxy → Juice Shop link still uses HTTP internally. While less risky than external traffic, Threagile flags it since internal networks can still be compromised.

`cross-site-scripting` — XSS is an application-layer vulnerability in Juice Shop's deliberately vulnerable code. Infrastructure hardening doesn't address input validation flaws, which require code-level fixes.

### Honesty check

Did the total drop more than 50%? If yes, what does that say about the cost-benefit
of these particular hardening changes vs. the work you'd need to fully eliminate the rest?

- No, the total dropped only ~17% (from 23 to 19). This reveals that infrastructure-level hardening addresses only a small subset of risks. The remaining risks are mostly application-layer vulnerabilities.
