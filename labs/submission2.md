# Lab 2 Submission — Threat Modeling with Threagile

## Task 1 — Threagile Baseline Model

### 1.1: Baseline Threat Model Generation

The baseline threat model was generated using Threagile with the provided model file `labs/lab2/threagile-model.yaml`. The following command was executed:

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 1.2: Generated Outputs Verification

The following files were successfully generated in `labs/lab2/baseline/`:
- ✅ `report.pdf` — Full PDF report with diagrams
- ✅ `data-flow-diagram.png` — Data flow diagram
- ✅ `data-asset-diagram.png` — Data asset diagram
- ✅ `risks.json` — Risk export in JSON format
- ✅ `stats.json` — Statistics export
- ✅ `technical-assets.json` — Technical assets export

### 1.3: Risk Analysis and Documentation

#### Risk Ranking Methodology

Composite scores were calculated using the following formula:
- **Composite Score** = `Severity*100 + Likelihood*10 + Impact`

Where:
- **Severity**: critical (5) > elevated (4) > high (3) > medium (2) > low (1)
- **Likelihood**: very-likely (4) > likely (3) > possible (2) > unlikely (1)
- **Impact**: high (3) > medium (2) > low (1)

#### Top 5 Risks

| Rank | Severity | Category | Asset | Likelihood | Impact | Composite Score | Title |
|------|----------|----------|-------|------------|--------|------------------|-------|
| 1 | elevated | unencrypted-communication | user-browser | likely | high | 433 | Unencrypted Communication named Direct to App (no proxy) between User Browser and Juice Shop Application transferring authentication data |
| 2 | elevated | unencrypted-communication | reverse-proxy | likely | medium | 432 | Unencrypted Communication named To App between Reverse Proxy and Juice Shop Application |
| 3 | elevated | cross-site-scripting | juice-shop | likely | medium | 432 | Cross-Site Scripting (XSS) risk at Juice Shop Application |
| 4 | elevated | missing-authentication | juice-shop | likely | medium | 432 | Missing Authentication covering communication link To App from Reverse Proxy to Juice Shop Application |
| 5 | medium | cross-site-request-forgery | juice-shop | very-likely | low | 241 | Cross-Site Request Forgery (CSRF) risk at Juice Shop Application via Direct to App (no proxy) from User Browser |

#### Composite Score Calculations

1. **Risk #1**: 4×100 + 3×10 + 3 = 400 + 30 + 3 = **433**
2. **Risk #2**: 4×100 + 3×10 + 2 = 400 + 30 + 2 = **432**
3. **Risk #3**: 4×100 + 3×10 + 2 = 400 + 30 + 2 = **432**
4. **Risk #4**: 4×100 + 3×10 + 2 = 400 + 30 + 2 = **432**
5. **Risk #5**: 2×100 + 4×10 + 1 = 200 + 40 + 1 = **241**

#### Analysis of Critical Security Concerns

The baseline threat model identified **23 total risks** with the following distribution:
- **Elevated severity**: 4 risks
- **Medium severity**: 14 risks
- **Low severity**: 5 risks

**Key Security Concerns:**

1. **Unencrypted Communication (Top Priority)**: The most critical risks involve unencrypted HTTP communication channels, particularly:
   - Direct browser-to-application communication without encryption exposes authentication tokens and credentials to interception
   - Internal proxy-to-application communication lacks encryption, creating potential attack vectors within the network

2. **Cross-Site Scripting (XSS)**: The Juice Shop application is vulnerable to XSS attacks, which could allow attackers to execute malicious scripts in users' browsers, potentially leading to session hijacking or data theft.

3. **Missing Authentication**: The communication link between the reverse proxy and the application lacks authentication mechanisms, allowing potential unauthorized access if the proxy is compromised.

4. **Cross-Site Request Forgery (CSRF)**: Despite having a lower composite score due to low impact, CSRF vulnerabilities are very likely to be exploited and could lead to unauthorized actions on behalf of authenticated users.

**Diagrams Reference:**
- Data flow diagram: `labs/lab2/baseline/data-flow-diagram.png`
- Data asset diagram: `labs/lab2/baseline/data-asset-diagram.png`
- Full report: `labs/lab2/baseline/report.pdf`

---

## Task 2 — HTTPS Variant & Risk Comparison

### 2.1: Secure Model Variant Creation

A secure variant of the model was created by copying the baseline model and making the following specific changes:

1. **User Browser → Direct to App**: Changed `protocol: http` to `protocol: https`
2. **Reverse Proxy → To App**: Changed `protocol: http` to `protocol: https`
3. **Persistent Storage**: Changed `encryption: none` to `encryption: transparent`

The secure model was saved as `labs/lab2/threagile-model.secure.yaml`.

### 2.2: Secure Variant Analysis Generation

The secure variant analysis was generated using:

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 2.3: Risk Comparison

#### Risk Category Delta Table

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

**Total Risks**: Baseline: 23 → Secure: 21 (**-2 risks**)

#### Delta Run Explanation

**Specific Changes Made to the Model:**

1. **HTTPS for Direct Browser Access**: Changed the `Direct to App (no proxy)` communication link from HTTP to HTTPS, encrypting all traffic between the user's browser and the Juice Shop application.

2. **HTTPS for Proxy-to-App Communication**: Changed the `To App` communication link from HTTP to HTTPS, ensuring encrypted communication between the reverse proxy and the application even on internal networks.

3. **Transparent Encryption for Persistent Storage**: Enabled transparent encryption for the persistent storage component, ensuring data at rest is encrypted.

**Observed Results in Risk Categories:**

The security improvements resulted in the following changes:

- **unencrypted-communication**: **-2 risks** (from 2 to 0)
  - Both unencrypted communication risks were eliminated:
    - Direct browser-to-app unencrypted communication risk removed
    - Reverse proxy-to-app unencrypted communication risk removed

- **unencrypted-asset**: **-1 risk** (from 2 to 1)
  - The persistent storage encryption change eliminated one unencrypted asset risk
  - One unencrypted asset risk remains (Juice Shop Application itself, which is a process-level concern)

**Analysis of Why These Changes Reduced Risks:**

1. **HTTPS Implementation Impact**:
   - **Eliminated Unencrypted Communication Risks**: By implementing HTTPS for both direct browser access and proxy-to-app communication, all data in transit is now encrypted. This directly addresses the top two risks identified in the baseline model (composite scores 433 and 432).
   - **Protection Against Man-in-the-Middle Attacks**: Encrypted communication channels prevent attackers from intercepting authentication tokens, credentials, and session data during transmission.
   - **Compliance with Security Best Practices**: HTTPS ensures that even if network traffic is intercepted, the data remains protected through strong encryption protocols.

2. **Persistent Storage Encryption Impact**:
   - **Reduced Unencrypted Asset Risk**: Enabling transparent encryption for persistent storage addresses the risk of data exposure if the storage volume is compromised. This is particularly important for a component storing sensitive data like user accounts, orders, and logs.
   - **Defense in Depth**: Even if an attacker gains access to the host filesystem, encrypted storage provides an additional layer of protection.

**Comparison of Diagrams:**

The diagrams generated for both variants show the same architectural structure, but the secure variant reflects the encryption improvements:
- **Data Flow Diagram**: Shows HTTPS connections instead of HTTP, indicating encrypted communication channels
- **Data Asset Diagram**: Shows the persistent storage with encryption enabled
- The overall architecture remains the same, but security controls are now properly configured

**Key Takeaways:**

1. **Significant Risk Reduction**: The implementation of HTTPS and storage encryption eliminated 3 critical risks (2 unencrypted communication + 1 unencrypted asset), representing a 13% reduction in total risks.

2. **Targeted Security Controls**: The changes specifically addressed the highest-priority risks (composite scores 433 and 432), demonstrating that targeted security improvements can have substantial impact.

3. **Remaining Risks**: While encryption improvements addressed communication and storage risks, other vulnerabilities remain (XSS, CSRF, missing authentication, etc.) that require additional security controls beyond encryption.

4. **Practical Security Value**: This exercise demonstrates how threat modeling can guide security improvements and measure their effectiveness through quantitative risk reduction.

---

## Summary

This lab successfully demonstrated:
- ✅ Automated threat model generation using Threagile
- ✅ Quantitative risk analysis using composite scoring methodology
- ✅ Impact measurement of security control implementation
- ✅ Systematic documentation of security findings and improvements

The baseline model identified 23 risks, with the top risks being unencrypted communication channels. The secure variant, implementing HTTPS and storage encryption, reduced total risks to 21, eliminating all unencrypted communication risks and one unencrypted asset risk.
