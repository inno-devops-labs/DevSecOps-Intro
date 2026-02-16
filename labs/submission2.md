## Lab 2 — Submission

### Top 5 Risks (from labs/lab2/baseline/risks.json)

| Severity | Category | Asset | Likelihood | Impact |
|---|---|---|---|---|
| elevated | unencrypted-communication | user-browser | likely | high |
| elevated | unencrypted-communication | reverse-proxy | likely | medium |
| elevated | missing-authentication | juice-shop | likely | medium |
| elevated | cross-site-scripting | juice-shop | likely | medium |
| medium | cross-site-request-forgery | juice-shop | very-likely | low |

### Category Delta (Baseline vs Secure)

| Category | Baseline | Secure | Δ |
|---|---:|---:|---:|
| container-baseimage-backdooring | 1 | 1 | 0 |
| cross-site-request-forgery | 2 | 2 | 0 |
| cross-site-scripting | 1 | 1 | 0 |
| missing-authentication | 1 | 1 | 0 |
| missing-authentication-second-factor | 2 | 2 | 0 |
| missing-build-infrastructure | 1 | 1 | 0 |
| missing-hardening | 2 | 2 | 0 |
| missing-identity-store | 1 | 1 | 0 |
| missing-vault | 1 | 1 | 0 |
| missing-waf | 1 | 1 | 0 |
| server-side-request-forgery | 2 | 2 | 0 |
| unencrypted-asset | 2 | 1 | -1 |
| unencrypted-communication | 2 | 0 | -2 |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

### Delta Run Explanation

In the hardened configuration, all network interactions were migrated to **HTTPS**, and encryption was activated for persistent storage.
Consequently, the risks associated with *unencrypted-communication* and *unencrypted-asset* were mitigated or fully removed.
This clearly shows that implementing encryption for data both in transit and at rest significantly decreases the overall threat surface.

