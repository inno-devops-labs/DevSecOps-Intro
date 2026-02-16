### Top 5 risks

| Name | Severity | Category | Asset | Likelihood | Impact |
|------|----------|----------|-------|------------|--------|
| Unencrypted Communication (Direct to App, no proxy) | elevated | unencrypted-communication | user-browser | likely | high |
| Unencrypted Communication (Reverse Proxy to App) | elevated | unencrypted-communication | reverse-proxy | likely | medium |
| Missing Authentication (Reverse Proxy to App) | elevated | missing-authentication | juice-shop | likely | medium |
| Cross-Site Scripting (XSS) | elevated | cross-site-scripting | juice-shop | likely | medium |
| Cross-Site Request Forgery (Direct to App path) | medium | cross-site-request-forgery | juice-shop | very-likely | low |

### Risk ranking methodology and composite score calculations

Ranking formula used:

`Composite score = Severity*100 + Likelihood*10 + Impact`

Numeric mapping:

- Severity: critical=5, elevated=4, high=3, medium=2, low=1
- Likelihood: very-likely=4, likely=3, possible=2, unlikely=1
- Impact: high=3, medium=2, low=1

Calculated scores for the Top 5:

1. Unencrypted Communication (Direct to App, no proxy): `4*100 + 3*10 + 3 = 433`
2. Unencrypted Communication (Reverse Proxy to App): `4*100 + 3*10 + 2 = 432`
3. Missing Authentication (Reverse Proxy to App): `4*100 + 3*10 + 2 = 432`
4. Cross-Site Scripting (XSS): `4*100 + 3*10 + 2 = 432`
5. Cross-Site Request Forgery (Direct to App path): `2*100 + 4*10 + 1 = 241`

Notes:

- There are no risks with severity `critical` in this baseline.
- Ties are expected with this weighted formula; score `432` appears for three different risk categories.

### Analysis of critical security concerns identified

Most significant concerns are concentrated around insecure web traffic and weak request handling:

- **Unencrypted communication paths** expose authentication/session data in transit, especially on the direct browser-to-app HTTP path.
- **Missing authentication on reverse-proxy to app communication** increases the blast radius of proxy compromise or misrouting.
- **XSS** remains high-priority because it can lead to session theft, account hijacking, and malicious actions in user context.
- **CSRF exposure** on the direct path indicates missing anti-forgery protections and weak request origin validation.

Immediate mitigation priorities should be to enforce TLS end-to-end, remove/disable direct HTTP access to the app, harden authentication boundaries between components, and implement robust browser-layer protections (input/output encoding, CSP, CSRF tokens).

### Risk category delta table
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

#### Specific changes made to the model

The secure variant changed transport/encryption-related attributes in the threat model:

- `persistent-storage.Encryption`: `0 -> 1` (unencrypted to encrypted at-rest setting).
- `reverse-proxy -> juice-shop` communication (`reverse-proxy>to-app`) protocol: `1 -> 2`.
- `user-browser -> juice-shop` communication (`user-browser>direct-to-app-no-proxy`) protocol: `1 -> 2`.

No major asset topology changes were introduced (same core assets and links), but security properties on selected assets/links were strengthened.

#### Observed results in risk categories

From baseline to secure:

- `unencrypted-communication`: `2 -> 0` (delta `-2`)
- `unencrypted-asset`: `2 -> 1` (delta `-1`)
- All other listed categories remained unchanged (`delta 0`), including `cross-site-scripting`, `cross-site-request-forgery`, and `missing-authentication`.

Severity mix in `stats.json` also improved:

- Elevated risks: `4 -> 2`
- Medium risks: `14 -> 13`
- Low risks: unchanged at `5`

#### Analysis of why these changes reduced/modified risks

- Upgrading both identified HTTP links to protocol `2` removes plaintext transmission assumptions for those paths, which directly explains elimination of `unencrypted-communication` findings.
- Enabling encryption on persistent storage reduces at-rest exposure, which explains the partial reduction in `unencrypted-asset` findings.
- Categories like XSS, CSRF, SSRF, and missing authentication did not change because they depend on application logic, request validation, and identity/control design rather than only transport/storage encryption flags.

#### Comparison of diagrams between baseline and secure variants

- Data flow diagrams: baseline and secure versions keep the same architecture layout (browser, proxy, app, storage, webhook), but secure reflects hardened communication assumptions.
- Data asset diagrams: baseline and secure contain the same primary assets/data relationships, with secure representing improved protection posture rather than different data ownership.
- Reports/diagrams used for comparison:
	- Baseline flow: `labs/lab2/baseline/data-flow-diagram.png`
	- Secure flow: `labs/lab2/secure/data-flow-diagram.png`
	- Baseline assets: `labs/lab2/baseline/data-asset-diagram.png`
	- Secure assets: `labs/lab2/secure/data-asset-diagram.png`
	- Baseline report: `labs/lab2/baseline/report.pdf`
	- Secure report: `labs/lab2/secure/report.pdf`

### Screenshots or references to generated diagrams

- Baseline data flow diagram: `labs/lab2/baseline/data-flow-diagram.png`
- Secure data flow diagram: `labs/lab2/secure/data-flow-diagram.png`
- Baseline data asset diagram: `labs/lab2/baseline/data-asset-diagram.png`
- Secure data asset diagram: `labs/lab2/secure/data-asset-diagram.png`
- Baseline report: `labs/lab2/baseline/report.pdf`
- Secure report: `labs/lab2/secure/report.pdf`

