# Lab 2: Threat Modeling with Threagile

**Student:** ellilin  
**Date:** 2025-02-14  
**Lab:** Threat Modeling with Threagile (OWASP Juice Shop v19.0.0)

---

## Executive Summary

This lab demonstrates the practical application of automated threat modeling using **Threagile** - an open-source Agile Threat Modeling Toolkit. Two variants of the OWASP Juice Shop architecture were analyzed:

1. **Baseline Model**: HTTP communication without encryption, unencrypted storage
2. **Secure Model**: HTTPS encryption for all communication links, transparent encryption for persistent storage

The analysis reveals how implementing basic security controls (TLS encryption, encrypted storage) directly reduces specific threat categories, demonstrating the value of "shifting left" security in the software development lifecycle.

---

## Task 1 — Threagile Baseline Model

### 1.1: Model Overview

The baseline threat model represents a local OWASP Juice Shop deployment with the following characteristics:

- **Architecture**: User Browser → Reverse Proxy (optional) → Juice Shop Application → Persistent Storage
- **Communication Protocol**: HTTP (unencrypted) for direct access and internal proxy-to-app communication
- **Storage Encryption**: None (data at rest is unencrypted)
- **Trust Boundaries**: Internet → Host → Container Network

**Generated Artifacts:**
- `labs/lab2/baseline/report.pdf` - Full threat model report
- `labs/lab2/baseline/data-flow-diagram.png` - Data flow diagram
- `labs/lab2/baseline/data-asset-diagram.png` - Data asset diagram
- `labs/lab2/baseline/risks.json` - Detailed risk export
- `labs/lab2/baseline/stats.json` - Statistical summary

### 1.2: Risk Analysis Methodology

**Composite Scoring Formula:**
```
Composite Score = (Severity × 100) + (Likelihood × 10) + Impact
```

**Weight Scales:**
- **Severity**: critical (5) > elevated (4) > high (3) > medium (2) > low (1)
- **Likelihood**: very-likely (4) > likely (3) > possible (2) > unlikely (1)
- **Impact**: high (3) > medium (2) > low (1)

**Example Calculation:**
- Risk: Unencrypted Communication (Severity: elevated=4, Likelihood: likely=3, Impact: high=3)
- Composite Score = (4 × 100) + (3 × 10) + 3 = **433**

### 1.3: Top 5 Baseline Risks

| Rank | Category | Severity | Likelihood | Impact | Composite Score | Asset |
|------|----------|----------|------------|--------|-----------------|-------|
| 1 | **Unencrypted Communication** (Direct to App) | elevated | likely | high | **433** | User Browser → Juice Shop |
| 2 | **Unencrypted Communication** (Proxy to App) | elevated | likely | medium | **432** | Reverse Proxy → Juice Shop |
| 3 | **Cross-Site Scripting (XSS)** | elevated | likely | medium | **432** | Juice Shop Application |
| 4 | **Missing Authentication** (Proxy to App) | elevated | likely | medium | **432** | Reverse Proxy → Juice Shop |
| 5 | **Cross-Site Request Forgery (CSRF)** | medium | very-likely | low | **334** | Juice Shop Application |

#### Critical Security Concerns

**1. Unencrypted Communication (Composite Score: 433)**
- **Issue**: Direct user browser to app communication uses HTTP without TLS
- **Impact**: Credentials, session tokens, and sensitive data transmitted in cleartext
- **Attack Vector**: Network sniffing, Man-in-the-Middle (MitM) attacks
- **Business Impact**: High - complete compromise of user authentication data and session hijacking

**2. Cross-Site Scripting (XSS) (Composite Score: 432)**
- **Issue**: Juice Shop is deliberately vulnerable to XSS attacks
- **Impact**: Malicious script execution in victim browsers, cookie theft, session hijacking
- **Attack Vector**: Stored XSS via product reviews, reflected XSS via search parameters
- **Business Impact**: Medium - user session compromise, potential data exfiltration

**3. Missing Authentication (Proxy to App) (Composite Score: 432)**
- **Issue**: No authentication between reverse proxy and Juice Shop application
- **Impact**: Internal trust boundary lacks authentication verification
- **Attack Vector**: Direct internal access if network controls fail
- **Business Impact**: Medium - bypass of security controls, unauthorized app access

**4. Unencrypted Asset (Composite Score: 232)**
- **Issue**: Both Juice Shop Application and Persistent Storage lack encryption
- **Impact**: Data at rest vulnerable to disk theft, container breakout
- **Attack Vector**: Physical access, container escape, host compromise
- **Business Impact**: Medium - exposure of all application data and user records

**5. Server-Side Request Forgery (SSRF) (Composite Score: 232)**
- **Issue**: Juice Shop makes outbound requests to webhook endpoints without validation
- **Impact**: Internal network scanning, data exfiltration via outbound requests
- **Attack Vector**: Malicious webhook URLs, profile image fetch abuse
- **Business Impact**: Low - potential internal network access, data leakage

### 1.4: Diagrams

**Data Flow Diagram**: `labs/lab2/baseline/data-flow-diagram.png`
- Shows trust boundaries between Internet, Host, and Container Network
- Visualizes unencrypted HTTP communication links (red indicators)
- Maps data flow from User Browser through optional Reverse Proxy to Juice Shop

**Data Asset Diagram**: `labs/lab2/baseline/data-asset-diagram.png`
- Displays all 5 data assets: User Accounts, Orders, Product Catalog, Tokens & Sessions, Logs
- Shows confidentiality/integrity/availability ratings per asset
- Visualizes asset relationships to technical components

---

## Task 2 — HTTPS Variant & Risk Comparison

### 2.1: Model Changes Made

Three specific security controls were implemented in the secure variant:

**1. User Browser → Direct to App Communication**
- **Baseline**: `protocol: http`
- **Secure**: `protocol: https`
- **Rationale**: Encrypt direct communication to prevent credential/token interception

**2. Reverse Proxy → App Communication**
- **Baseline**: `protocol: http`
- **Secure**: `protocol: https`
- **Rationale**: Encrypt internal proxy-to-app communication for defense-in-depth

**3. Persistent Storage Encryption**
- **Baseline**: `encryption: none`
- **Secure**: `encryption: transparent`
- **Rationale**: Protect data at rest from disk theft, container breakout, or host compromise

### 2.2: Risk Category Delta Table

| Category | Baseline | Secure | Δ | Change |
|-----------|-----------|--------|---|--------|
| container-baseimage-backdooring | 1 | 1 | 0 | No change |
| cross-site-request-forgery | 2 | 2 | 0 | No change |
| cross-site-scripting | 1 | 1 | 0 | No change |
| missing-authentication | 1 | 1 | 0 | No change |
| missing-authentication-second-factor | 2 | 2 | 0 | No change |
| missing-build-infrastructure | 1 | 1 | 0 | No change |
| missing-hardening | 2 | 2 | 0 | No change |
| missing-identity-store | 1 | 1 | 0 | No change |
| missing-vault | 1 | 1 | 0 | No change |
| missing-waf | 1 | 1 | 0 | No change |
| server-side-request-forgery | 2 | 2 | 0 | No change |
| **unencrypted-asset** | **2** | **1** | **-1** | ✅ **Reduced** |
| **unencrypted-communication** | **2** | **0** | **-2** | ✅ **Eliminated** |
| unnecessary-data-transfer | 2 | 2 | 0 | No change |
| unnecessary-technical-asset | 2 | 2 | 0 | No change |

### 2.3: Delta Analysis

**Total Risks Reduced: 3 out of 23 (13% reduction)**

#### Risk Eliminated: Unencrypted Communication (-2 risks)

**Before:**
- `unencrypted-communication` on User Browser → Juice Shop (elevated severity)
- `unencrypted-communication` on Reverse Proxy → Juice Shop (elevated severity)

**After:**
- Both communication links now use HTTPS protocol
- Threagile's rule engine no longer detects unencrypted communication
- Both risks completely eliminated from the threat model

**Security Impact:**
- **Confidentiality**: Credentials, session tokens, and sensitive user data now encrypted in transit
- **Attack Surface Reduction**: Network sniffing and Man-in-the-Middle (MitM) attacks no longer possible on these links
- **Compliance**: Meets security best practices for web application communication (OWASP ASVS)

#### Risk Reduced: Unencrypted Asset (-1 risk)

**Before:**
- Persistent Storage had `encryption: none` (unencrypted asset risk)

**After:**
- Persistent Storage now has `encryption: transparent`
- One `unencrypted-asset` risk eliminated (Persistent Storage)
- Juice Shop Application still lacks encryption (container-level encryption would be needed for complete elimination)

**Security Impact:**
- **Confidentiality**: Data at rest (database, logs, uploads) now protected by transparent encryption
- **Attack Surface Reduction**: Disk theft or container breakout no longer directly exposes sensitive data
- **Defense in Depth**: Encryption at rest complements encryption in transit

#### Unchanged Risks (20 out of 23)

Many risks remain unchanged because they address **application-level vulnerabilities** that are independent of transport encryption:

- **Cross-Site Scripting (XSS)**: Application-level injection vulnerability - TLS doesn't prevent XSS
- **Cross-Site Request Forgery (CSRF)**: Application lack of CSRF tokens - unrelated to transport encryption
- **Missing Authentication**: Lack of authentication on proxy-to-app link - still present even with HTTPS
- **Missing Hardening**: Security hardening issues - independent of encryption
- **Server-Side Request Forgery (SSRF)**: Application-level outbound request validation - unrelated to TLS
- **Missing 2FA**: Lack of multi-factor authentication - application-level control

**Key Insight**: Implementing HTTPS and encryption at rest effectively eliminates network and storage-level risks, but **application-level security controls** remain essential. This demonstrates the need for **defense in depth** - security controls at multiple layers (network, application, data).

### 2.4: Diagram Comparison

**Baseline Diagram** (`labs/lab2/baseline/data-flow-diagram.png`):
- HTTP communication links visible (unencrypted indicators)
- Clear visualization of trust boundary crossings

**Secure Diagram** (`labs/lab2/secure/data-flow-diagram.png`):
- All communication links now show HTTPS
- Trust boundary crossings remain, but with encrypted transport

---

## Conclusions

### Key Learnings

1. **Automated Threat Modeling Works**: Threagile successfully analyzed a YAML-as-code model and generated actionable risk reports, demonstrating the value of "threat modeling as code" in DevSecOps workflows.

2. **Security Controls Have Measurable Impact**: Implementing HTTPS and transparent encryption reduced the threat landscape by 3 risks (13%), proving that basic security controls have tangible effects on the risk profile.

3. **Defense in Depth is Critical**: While HTTPS and encryption addressed network and storage risks, 20 application-level risks remained unchanged. This underscores that **security must be applied at multiple layers** - network, application, and data - to achieve comprehensive protection.

4. **Threat Modeling Prioritization**: The composite scoring methodology helped identify the most critical risks (Unencrypted Communication: 433, XSS: 432), enabling focused remediation efforts on high-impact threats.

5. **Model-Driven Security**: The Threagile YAML model serves as living documentation that can be versioned, reviewed, and integrated into CI/CD pipelines for continuous threat modeling.

### Recommendations for OWASP Juice Shop

Based on the threat modeling analysis, the following security improvements would significantly reduce the threat landscape:

**Priority 1 (High Impact):**
1. **Enforce HTTPS** for all user-facing communication (already implemented in secure model)
2. **Implement Transparent Encryption** for persistent storage (already implemented in secure model)
3. **Add CSRF Tokens** to prevent Cross-Site Request Forgery attacks
4. **Enable Authentication** on the reverse proxy to Juice Shop link

**Priority 2 (Medium Impact):**
5. **Implement XSS Filtering** and output encoding to prevent cross-site scripting
6. **Add Web Application Firewall (WAF)** to detect and block common attack patterns
7. **Implement Rate Limiting** to prevent credential stuffing and brute force attacks
8. **Add Multi-Factor Authentication (MFA)** for sensitive operations

**Priority 3 (Operational):**
9. **Implement Secret Management** (vault) for storing sensitive configuration
10. **Add Build Infrastructure** with security scanning (SAST/DAST/SCA) in CI/CD

---

## Generated Artifacts

### Baseline Model Outputs
- `labs/lab2/baseline/report.pdf` - Full PDF threat model report
- `labs/lab2/baseline/data-flow-diagram.png` - Visual data flow diagram
- `labs/lab2/baseline/data-asset-diagram.png` - Visual data asset diagram
- `labs/lab2/baseline/risks.json` - Machine-readable risk export
- `labs/lab2/baseline/stats.json` - Statistical summary
- `labs/lab2/baseline/technical-assets.json` - Asset inventory

### Secure Model Outputs
- `labs/lab2/secure/report.pdf` - Full PDF threat model report (secure variant)
- `labs/lab2/secure/data-flow-diagram.png` - Visual data flow diagram (secure variant)
- `labs/lab2/secure/data-asset-diagram.png` - Visual data asset diagram (secure variant)
- `labs/lab2/secure/risks.json` - Machine-readable risk export (secure variant)
- `labs/lab2/secure/stats.json` - Statistical summary (secure variant)
- `labs/lab2/secure/technical-assets.json` - Asset inventory (secure variant)

### Model Files
- `labs/lab2/threagile-model.yaml` - Baseline threat model (as code)
- `labs/lab2/threagile-model.secure.yaml` - Secure variant threat model (as code)

---

## References

- **Threagile**: https://threagile.io - Open-source Agile Threat Modeling Toolkit
- **OWASP Juice Shop**: https://owasp.org/www-project-juice-shop - Deliberately vulnerable web application
- **OWASP Top 10**: https://owasp.org/www-project-top-ten - Critical web application security risks
- **STRIDE Framework**: Microsoft threat modeling methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
