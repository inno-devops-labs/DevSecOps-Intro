# Submission 2

## Top 5 Risks by Composite score

Based on the threat model report, I'll calculate composite risk scores and identify the top 5 risks.

| Rank | Risk Category | Severity | Asset | Likelihood | Impact | Composite Score |
|------|---------------|----------|-------|------------|--------|-----------------|
| 1 | Unencrypted Communication | Elevated (4) | User Browser ↔ Juice Shop App | Likely (3) | High (3) | 433 |
| 2 | Cross-Site Scripting (XSS) | Elevated (4) | Juice Shop Application | Likely (3) | Medium (2) | 432 |
| 3 | Missing Authentication | Elevated (4) | Reverse Proxy → Juice Shop App | Likely (3) | Medium (2) | 432 |
| 4 | Unencrypted Communication | Elevated (4) | Reverse Proxy ↔ Juice Shop App | Likely (3) | Medium (2) | 432 |
| 5 | Cross-Site Request Forgery (CSRF) | Medium (2) | Juice Shop Application | Very Likely (4) | Low (1) | 241 |

## Critical Security Concerns Analysis

1. Communication Security (Highest Priority)

- Unencrypted HTTP communication between components poses the highest risk
- Direct browser access on port 3000 transmits authentication data unencrypted
- Even reverse proxy communication to the app remains unencrypted internally

2. Authentication & Authorization Gaps

- Missing authentication between reverse proxy and application
- No two-factor authentication implemented
- CSRF vulnerabilities with very high likelihood of exploitation

3. Application Security Vulnerabilities

- Cross-site scripting risks in the Juice Shop application
- Server-side request forgery vulnerabilities
- Missing input validation and output encoding

4. Infrastructure Security

- Container base image backdooring risks
- Missing system hardening for high-RAA assets
- No secret management vault in place

5. Architectural Model Gaps

- Missing build infrastructure in threat model
- No identity store modeled
- Unnecessary data transfers identified

Most Affected Assets:

- Juice Shop Application: 13 risks
- Persistent Storage: 3 risks
- User Browser: 4 risks
- Reverse Proxy: 3 risks

The communication security risk is one of the most critical and both the simplest to defend against. This should be addressed firstly, implementing proper traffic encryption. The application, infrastructure and architectural risks should be managed by executing an audit of the application and identifying high-severity issues and highlight potentially weak points.

## Risk category delta

The delta of risks between baseline and secure models:

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

## Delta Run Explaination

As we can see, three risks were mitigating by adding encryption to HTTP communications. The mitigated risks are:

- unencrypted-asset
- unencrypted-communication

The unecrypted-asset risk was mitigated by adding encryption to the persistent storage, and the two unencrypted communications were secured by adding HTTPs

# Diagrams comparison

We can see clear difference on data-flow-diagram.png, now the diagram shows encrypted protocol usage:

![secure-diagram](./lab2/secure/data-flow-diagram.png)