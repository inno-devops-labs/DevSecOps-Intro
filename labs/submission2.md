# Lab 2 — Threat Modeling with Threagile

## Task 1 — Threagile Baseline Model Analysis

### Generated Outputs
Successfully generated baseline threat model using Threagile with the following artifacts:
- `labs/lab2/baseline/report.pdf` - Complete threat model report with diagrams
- `labs/lab2/baseline/data-flow-diagram.png` - Data flow visualization
- `labs/lab2/baseline/data-asset-diagram.png` - Data asset relationships
- `labs/lab2/baseline/risks.json` - Detailed risk analysis
- `labs/lab2/baseline/stats.json` - Risk statistics summary

### Top 5 Risks Analysis

Using the composite scoring formula: `Severity*100 + Likelihood*10 + Impact`

| Rank | Category | Severity | Asset | Likelihood | Impact | Composite Score | Risk Description |
|------|----------|----------|-------|------------|--------|-----------------|------------------|
| 1 | unencrypted-communication | elevated (4) | user-browser | likely (3) | high (3) | 433 | Direct HTTP communication exposing authentication data |
| 2 | unencrypted-communication | elevated (4) | reverse-proxy | likely (3) | medium (2) | 432 | Internal HTTP traffic between proxy and app |
| 3 | cross-site-scripting | elevated (4) | juice-shop | likely (3) | medium (2) | 432 | XSS vulnerabilities in the web application |
| 4 | missing-authentication | elevated (4) | juice-shop | likely (3) | medium (2) | 432 | Missing authentication on proxy-to-app communication |
| 5 | server-side-request-forgery | medium (3) | juice-shop | likely (3) | low (1) | 331 | SSRF risks in webhook functionality |

### Risk Ranking Methodology
- **Severity weights**: critical (5) > elevated (4) > high (3) > medium (2) > low (1)
- **Likelihood weights**: very-likely (4) > likely (3) > possible (2) > unlikely (1)
- **Impact weights**: high (3) > medium (2) > low (1)
- **Composite score** provides prioritized risk ranking for mitigation planning

### Critical Security Concerns
1. **Unencrypted Communication**: The highest risks involve HTTP traffic exposing sensitive authentication data
2. **XSS Vulnerabilities**: Elevated XSS risk in the deliberately vulnerable Juice Shop application
3. **Missing Authentication**: Gaps in authentication controls between components
4. **SSRF Potential**: Server-side request forgery in outbound webhook functionality

---

## Task 2 — HTTPS Variant & Risk Comparison

### Security Model Changes
Created secure variant (`threagile-model.secure.yaml`) with specific improvements:
1. **User Browser → Direct to App**: Changed `protocol: http` to `protocol: https`
2. **Reverse Proxy → App**: Changed `protocol: http` to `protocol: https`  
3. **Persistent Storage**: Changed `encryption: none` to `encryption: transparent`

### Risk Category Delta Analysis

| Category | Baseline | Secure | Δ | Analysis |
|----------|----------|---------|---|----------|
| container-baseimage-backdooring | 1 | 1 | 0 | Unchanged - container security unaffected |
| cross-site-request-forgery | 2 | 2 | 0 | Unchanged - CSRF protection needed |
| cross-site-scripting | 1 | 1 | 0 | Unchanged - application-level vulnerability |
| missing-authentication | 1 | 1 | 0 | Unchanged - auth controls still needed |
| missing-authentication-second-factor | 2 | 2 | 0 | Unchanged - 2FA still recommended |
| missing-build-infrastructure | 1 | 1 | 0 | Unchanged - CI/CD security needed |
| missing-hardening | 2 | 2 | 0 | Unchanged - system hardening required |
| missing-identity-store | 1 | 1 | 0 | Unchanged - identity management needed |
| missing-vault | 1 | 1 | 0 | Unchanged - secret management required |
| missing-waf | 1 | 1 | 0 | Unchanged - WAF protection recommended |
| server-side-request-forgery | 2 | 2 | 0 | Unchanged - SSRF protection needed |
| **unencrypted-asset** | **2** | **1** | **-1** | **Reduced by storage encryption** |
| **unencrypted-communication** | **2** | **0** | **-2** | **Eliminated by HTTPS implementation** |
| unnecessary-data-transfer | 2 | 2 | 0 | Unchanged - data minimization needed |
| unnecessary-technical-asset | 2 | 2 | 0 | Unchanged - architecture review needed |

### Delta Analysis Explanation

**Key Security Improvements:**
1. **HTTPS Implementation (-2 risks)**: Completely eliminated unencrypted communication risks by implementing TLS for both direct browser access and proxy-to-app communication
2. **Storage Encryption (-1 risk)**: Reduced unencrypted asset risks through transparent encryption of persistent storage

**Why Changes Reduced Risks:**
- **HTTPS** addresses the highest-severity risks by encrypting authentication data in transit, preventing credential interception and session hijacking
- **Transparent encryption** protects data at rest, reducing the impact of storage compromise
- **Risk reduction demonstrates** how transport-layer security significantly improves overall security posture

**Unchanged Risk Categories:**
- Application-level vulnerabilities (XSS, CSRF, SSRF) require code-level fixes
- Infrastructure security (WAF, hardening, vault) needs additional security controls
- Authentication and identity management risks remain without additional controls

### Diagram Comparison
- **Baseline**: Shows HTTP communication paths and unencrypted storage
- **Secure**: Illustrates HTTPS-protected communication and encrypted storage
- **Visual difference**: Clear representation of security control improvements

---

## Conclusion

Threagile successfully demonstrated how threat modeling can:
1. **Systematically identify** security risks across application architecture
2. **Prioritize risks** using composite scoring for effective mitigation planning
3. **Quantify security improvements** through baseline vs. secure variant comparison
4. **Guide security investments** by showing which controls provide the greatest risk reduction

The analysis confirms that implementing HTTPS provides the most significant security improvement, eliminating the highest-severity risks while other application-level vulnerabilities require additional security controls and code changes.
