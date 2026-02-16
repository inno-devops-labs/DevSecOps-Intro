# Lab 2 — Threat Modeling with Threagile

## Task 1 — Baseline Threat Model

### Top 5 Risks

| Risk | Category | Severity |
|-----|----------|----------|
| Cross-Site Scripting (XSS) risk at Juice Shop Application | cross-site-scripting | elevated |
| Unencrypted Communication between User Browser and Juice Shop Application | unencrypted-communication | elevated |
| Unencrypted Communication between Reverse Proxy and Juice Shop Application | unencrypted-communication | elevated |
| Missing Authentication between Reverse Proxy and Juice Shop Application | missing-authentication | elevated |
| Unencrypted Technical Asset Persistent Storage | unencrypted-asset | medium |

---

### Risk Analysis

The most critical risks identified in the baseline model are related to unencrypted communication and missing authentication mechanisms.

Unencrypted communication between components exposes sensitive data such as credentials and session tokens to interception attacks. This significantly increases the risk of data breaches and session hijacking.

Cross-Site Scripting (XSS) is another major risk, allowing attackers to inject malicious scripts into the application, potentially compromising user sessions and sensitive data.

Additionally, the lack of authentication controls and unencrypted storage increases the overall attack surface and risk of unauthorized access.

---

### Generated Artifacts

Baseline threat model outputs generated successfully:

- report.pdf
- risks.json
- stats.json
- technical-assets.json
- data-flow-diagram.png
- data-asset-diagram.png

---

## Task 2 — Secure Model and Risk Comparison

### Changes Applied

The following security improvements were implemented in the secure model:

- Changed communication protocols from HTTP to HTTPS
- Enabled encryption for Persistent Storage using transparent encryption

These changes improve data protection in transit and at rest.

---

### Risk Comparison Table

| Category | Baseline | Secure | Delta |
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

---

### Analysis of Security Improvements

The secure model demonstrates a reduction in risks related to unencrypted communication and storage.

Specifically:

- Unencrypted communication risks were completely eliminated (-2), confirming that HTTPS effectively protects data in transit.
- Unencrypted asset risks were reduced (-1), showing that enabling storage encryption improves data security at rest.

These improvements significantly strengthen the security posture of the application by protecting sensitive information from interception and unauthorized access.

Overall, implementing HTTPS and encryption is an effective mitigation strategy that reduces critical attack vectors.
