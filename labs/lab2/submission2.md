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

