# Threat Modeling with Threagile

### Task 1 — Threagile Baseline Model

#### Top 5 risks

| Rank | Category                    | Asset                                                            | Severity     | Likelihood | Impact     | Composite Score |
| ---- | --------------------------- | ---------------------------------------------------------------- | ------------ | ---------- | ---------- | --------------- |
| 1    | unencrypted-communication   | User Browser → Juice Shop Application (Direct to App)            | elevated (4) | likely (3) | high (3)   | 434             |
| 2    | unencrypted-communication   | Reverse Proxy → Juice Shop Application (To App)                  | elevated (4) | likely (3) | medium (2) | 432             |
| 3    | cross-site-scripting        | Juice Shop Application                                           | elevated (4) | likely (3) | medium (2) | 432             |
| 4    | missing-authentication      | Reverse Proxy → Juice Shop Application (To App)                  | elevated (4) | likely (3) | medium (2) | 432             |
| 5    | server-side-request-forgery | Juice Shop Application → Webhook Endpoint (To Challenge WebHook) | medium (2)   | likely (3) | low (1)    | 231             |


#### Critical Security Concerns

Primary Issues:

- Unencrypted HTTP traffic exposes authentication tokens/sessions: 
    - Direct browser→app connection (elevated risk, score 434)
    - Internal proxy→app traffic (elevated risk, score 432)
- XSS vulnerability in Juice Shop Application (elevated, score 432)
- Missing internal authentication between proxy→app (elevated, score 432)

Impact: These elevated risks create multiple attack vectors for token theft, session hijacking, and code injection targeting sensitive data assets (user-accounts, orders, tokens-sessions)

#### Artifacts
![Data asset diagram](./baseline/data-asset-diagram.png)
![Data flow diagram](./baseline/data-flow-diagram.png)

### Task 2 — HTTPS Variant & Risk Comparison

### Risk Category Delta Table

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
| **unencrypted-asset** | **2** | **1** | **-1** |
| **unencrypted-communication** | **2** | **0** | **-2** |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

Observed Results:
- Гnencrypted-communication: 2 => 0 (-2) - Both HTTP links fixed
- Гnencrypted-asset: 2 => 1 (-1) - Storage encrypted, Juice Shop app remains unencrypted
- Total risk reduction: 3 risks eliminated (13.0% of total baseline risks)

Why Changes Reduced Risks:
- Unencrypted communication risks had highest composite scores (434, 432) due to token/session exposure over public HTTP
- Encryption directly addresses CIA triad Confidentiality requirements for data-at-rest (persistent storage)
- Changes target root causes: protocol configuration and asset encryption flags in Threagile YAML

### Diagram Comparison
- Baseline Diagram shows:
![Baseline](./baseline/data-flow-diagram.png)

- Secure diagram:
![Secure](./secure/data-flow-diagram.png)

We can observe that `https` communication is used between:
- `user browser` and `reverse proxy`
- AND `reverse proxy` and `app container`

This enforces security, making MiTM attacks useless