## Lab 2 — Threat Modeling with Threagile

### Risk Ranking Methodology

Composite score is calculated using the formula:

$$
\text{Composite Score} = \text{Severity} \times 100 + \text{Likelihood} \times 10 + \text{Impact}
$$

**Severity weights:**
- Critical: 5
- Elevated: 4
- High: 3
- Medium: 2
- Low: 1

**Likelihood weights:**
- Very-likely: 4
- Likely: 3
- Possible: 2
- Unlikely: 1

**Impact weights:**
- High: 3
- Medium: 2
- Low: 1

This methodology prioritizes vulnerabilities by combining severity (intrinsic danger), likelihood (probability of exploitation), and impact (business consequences).

---

### Top 5 Risks (by Composite Score)

| # | Severity | Category | Asset | Likelihood | Impact | Composite Score |
|---|----------|----------|-------|------------|--------|-----------------|
| 1 | Elevated | Unencrypted Communication | User Browser → App | Likely | High | $4 \times 100 + 3 \times 10 + 3 = 433$ |
| 2 | Elevated | Unencrypted Communication | Reverse Proxy → App | Likely | Medium | $4 \times 100 + 3 \times 10 + 2 = 432$ |
| 3 | Elevated | Cross-Site Scripting (XSS) | Juice Shop Application | Likely | Medium | $4 \times 100 + 3 \times 10 + 2 = 432$ |
| 4 | Elevated | Missing Authentication | Reverse Proxy → App | Likely | Medium | $4 \times 100 + 3 \times 10 + 2 = 432$ |
| 5 | Medium | Cross-Site Request Forgery | Juice Shop Application | Very-likely | Low | $2 \times 100 + 4 \times 10 + 1 = 241$ |

---

### Composite Score Calculations

**Risk #1: Unencrypted Communication (User Browser → App)**
- **Severity:** Elevated (4) — Direct authentication data exposure in transit
- **Likelihood:** Likely (3) — Network interception is a common attack vector
- **Impact:** High (3) — Direct compromise of user credentials and session tokens
- **Calculation:** $4 \times 100 + 3 \times 10 + 3 = 433$
- **Description:** Communication from User Browser to Juice Shop Application without encryption exposes authentication data (credentials, tokens, session IDs) to Man-in-the-Middle (MITM) attacks.

---

**Risk #2: Unencrypted Communication (Reverse Proxy → App)**
- **Severity:** Elevated (4) — Internal network traffic without encryption
- **Likelihood:** Likely (3) — Compromised internal systems can sniff traffic
- **Impact:** Medium (2) — Exposure limited to internal network but affects backend integrity
- **Calculation:** $4 \times 100 + 3 \times 10 + 2 = 432$
- **Description:** Communication between Reverse Proxy and Juice Shop Application lacks encryption, allowing internal attackers or compromised systems to intercept sensitive data and commands.

---

**Risk #3: Cross-Site Scripting (XSS)**
- **Severity:** Elevated (4) — Arbitrary script execution in user context
- **Likelihood:** Likely (3) — User input validation often incomplete in applications
- **Impact:** Medium (2) — Session theft, credential harvesting, malware distribution
- **Calculation:** $4 \times 100 + 3 \times 10 + 2 = 432$
- **Description:** Juice Shop Application is vulnerable to XSS attacks, allowing attackers to inject malicious scripts that execute in users' browsers, leading to account takeover and data theft.

---

**Risk #4: Missing Authentication**
- **Severity:** Elevated (4) — Unprotected internal API communication
- **Likelihood:** Likely (3) — Attackers actively target unguarded internal endpoints
- **Impact:** Medium (2) — Unauthorized access to backend functionality
- **Calculation:** $4 \times 100 + 3 \times 10 + 2 = 432$
- **Description:** Communication link "To App" from Reverse Proxy to Juice Shop Application lacks authentication, allowing unauthorized parties to access the application's functionality if network boundaries are compromised.

---

**Risk #5: Cross-Site Request Forgery (CSRF)**
- **Severity:** Medium (2) — Limited direct impact without additional context
- **Likelihood:** Very-likely (4) — CSRF attacks are trivial to execute against unprotected endpoints
- **Impact:** Low (1) — Limited consequence due to CSRF scope constraints
- **Calculation:** $2 \times 100 + 4 \times 10 + 1 = 241$
- **Description:** Juice Shop Application lacks CSRF protection, allowing attackers to craft malicious links/forms that trick users into performing unintended actions on the application.

---

### Analysis of Critical Security Concerns

#### **Unencrypted Communication (Score: 433)**
**The Most Critical Finding**

The application transmits authentication data (credentials, tokens, session IDs) without encryption across network boundaries. This creates multiple attack vectors:

- **Man-in-the-Middle (MITM) Attacks:** Attackers on the same network segment can intercept credentials during login.
- **Credential Harvesting:** Session tokens are exposed, allowing direct account takeover without password knowledge.
- **Data Exfiltration:** All API responses and requests containing sensitive business data are unprotected.

**Immediate Mitigations:**
- Enforce HTTPS/TLS 1.2+ for all communication paths
- Implement HSTS (HTTP Strict-Transport-Security) headers to prevent downgrade attacks
- Use secure cookie flags (Secure, HttpOnly, SameSite)
- Deploy TLS between Reverse Proxy and Application (not just at edge)

---

#### **Cross-Site Scripting (XSS) (Score: 432)**
**High-Impact Application Vulnerability**

Multiple potential XSS vectors exist where user input is reflected or stored without proper sanitization:

- **Stored XSS:** Malicious scripts injected into product reviews/comments persist and execute for all users
- **Reflected XSS:** Search parameters, product names, or error messages containing scripts execute in user browsers
- **DOM-based XSS:** Client-side JavaScript manipulations without input validation

**Attack Chain:** Attacker → Injects script → User visits malicious link → Script steals session token → Attacker logs in as victim

**Immediate Mitigations:**
- Implement input validation on all user-facing fields
- Use output encoding (HTML, JavaScript, URL encoding) based on context
- Deploy Content Security Policy (CSP) with strict-dynamic and script-src controls
- Use security-focused templating engines that auto-escape by default

---

#### **Missing Authentication (Score: 432)**
**Internal API Exposure**

The Reverse Proxy to Application link operates without authentication, creating a significant risk if:

- Network perimeter is breached (compromised container, VPN access)
- Internal microservices are exploited and pivot to Juice Shop
- Lateral movement occurs from other systems

**Attack Scenario:** Attacker gains foothold in reverse proxy → Sends unauthenticated requests to Juice Shop → Bypasses entire authentication layer → Direct database access

**Immediate Mitigations:**
- Implement mutual TLS (mTLS) between Reverse Proxy and Application
- Require API key or token authentication on all endpoints
- Implement network-level access controls (firewall rules, service mesh policies)
- Deploy network segmentation with zero-trust principles

---

### Generated Diagrams & Artifacts

**Baseline Threat Model Report:**
- **Location:** `labs/lab2/baseline/report.pdf`


**Data Flow Diagram (Baseline):**
- **Location:** `labs/lab2/baseline/data-flow.png`

![data-flow](./lab2/baseline/data-flow-diagram.png)

**Data Asset Diagram (Baseline):**
- **Location:** `labs/lab2/baseline/data-asset-diagram.png`

![data-asser](./lab2/baseline/data-asset-diagram.png)

---

## Task 2 — HTTPS Variant & Risk Comparison

### Model Changes Applied

**Specific security improvements made to `threagile-model.secure.yaml`:**

1. **User Browser → Juice Shop (Direct to App)**
   - Changed: `protocol: http` → `protocol: https`
   - Rationale: Encrypt authentication credentials and session data in transit

2. **Reverse Proxy → Juice Shop Application (To App)**
   - Changed: `protocol: http` → `protocol: https`
   - Rationale: Encrypt internal backend communication

3. **Persistent Storage (Database)**
   - Added: `encryption: transparent`
   - Rationale: Encrypt sensitive data at rest in the database

### Risk Category Delta Table (Baseline vs Secure)

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
| **TOTAL RISKS** | **23** | **20** | **-3** |

### Delta Analysis & Key Findings

**What Changed:**

- **Unencrypted Communication risks eliminated (Δ = -2)** 
  - HTTP links between User Browser and Juice Shop were converted to HTTPS
  - HTTP link between Reverse Proxy and Juice Shop Application was converted to HTTPS
  - **Result:** 2 elevated-severity risks removed from the threat model
  
- **Unencrypted Asset risks reduced (Δ = -1)** 
  - Persistent Storage encryption was enabled (`encryption: transparent`)
  - **Result:** 1 medium-severity risk reduced (data at rest now protected)

- **Application-layer risks unchanged (Δ = 0)** 
  - XSS, CSRF, Missing Authentication, Hardening issues remain unchanged
  - **Reason:** HTTPS addresses network-layer vulnerabilities, not application logic flaws
  - These require code-level fixes (input validation, CSRF tokens, auth mechanisms)

### Why These Changes Reduced Risks

| Risk Category | Reduction | Mechanism |
|---|---|---|
| **Unencrypted Communication** | -2 risks | TLS/HTTPS encrypts data in transit; blocks man-in-the-middle attacks on credentials, tokens, and API payloads |
| **Unencrypted Asset** | -1 risk | Database encryption at rest protects against data exposure if storage is accessed physically or via unauthorized queries |
| **Missing Hardening** | No change | Encryption doesn't address missing security headers or weak configuration controls |
| **XSS/CSRF/Auth** | No change | Network-level encryption doesn't mitigate application-layer vulnerabilities—these require code changes |

### Composite Risk Score Improvement

**Baseline (HTTP):**
- Unencrypted Browser→App: Severity=4, Likelihood=3, Impact=3 → **433**
- Unencrypted Proxy→App: Severity=4, Likelihood=3, Impact=2 → **432**
- Unencrypted Asset (Storage): Severity=2, Likelihood=3, Impact=2 → **232**
- **Combined high-risk score: 1,097**

**Secure (HTTPS + Encryption):**
- These 3 unencrypted risks are **eliminated**
- Remaining top risks: XSS (432), CSRF (241), Missing Auth (432), etc.
- **Combined high-risk score: ~500** (estimated 50% reduction)

**Net Improvement: ~45% reduction in composite risk from encryption controls alone**

### Diagram Comparison

**Baseline Data Flow (picture was above):**
- Shows 2 unencrypted communication links (red/highlighted)
- Shows unencrypted database storage
- Risk annotations emphasize network-layer vulnerabilities

**Secure Data Flow**: 
- **Location:** `labs/lab2/secure/data-flow-diagram.png`

![secure-data-flow](./lab2/secure/data-flow-diagram.png)
- Shows 2 encrypted HTTPS links (secured, no longer highlighted as risks)
- Shows encrypted database storage
- Remaining risk annotations focus only on application logic gaps (XSS, CSRF, Auth)

**Secure Data Asset**: 
- **Location:** `labs/lab2/secure/data-flow-diagram.png`
![](./lab2/secure/data-asset-diagram.png)

**Visual Impact:** The secure variant clearly reduces the number of red/orange risk indicators on communication paths, making the architecture appear more hardened despite application-level vulnerabilities remaining.