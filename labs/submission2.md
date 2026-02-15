# Lab 2 — Threat Modeling with Threagile

## Task 1 — Baseline Threat Model


### 1.1 Risk Ranking Methodology

Each risk was ranked using the required composite score formula:

```
Composite Score = Severity × 100 + Likelihood × 10 + Impact
```


**Weights used:**

- **Severity:**  
  critical (5), elevated (4), high (3), medium (2), low (1)

- **Likelihood:**  
  very-likely (4), likely (3), possible (2), unlikely (1)

- **Impact:**  
  high (3), medium (2), low (1)

Risks were sorted by descending composite score to identify the most critical security concerns.

---

### 1.2 Top 5 Risks (Baseline)

| # | Risk Category | Affected Asset / Link | Severity | Likelihood | Impact | Composite Score |
|---|--------------|-----------------------|----------|------------|--------|-----------------|
| 1 | Unencrypted Communication | User Browser → Juice Shop (Direct) | Elevated (4) | Likely (3) | High (3) | **433** |
| 2 | Cross-Site Scripting (XSS) | Juice Shop Application | Elevated (4) | Likely (3) | Medium (2) | **432** |
| 3 | Missing Authentication | Reverse Proxy → Juice Shop | Elevated (4) | Likely (3) | Medium (2) | **432** |
| 4 | Unencrypted Communication | Reverse Proxy → Juice Shop | Elevated (4) | Likely (3) | Medium (2) | **432** |
| 5 | Cross-Site Request Forgery (CSRF) | User Browser → Juice Shop | Medium (2) | Very-Likely (4) | Low (1) | **241** |

---

### 1.3 Baseline Risk Analysis

Key security observations:

- **Plaintext HTTP communication** is the most critical issue, exposing credentials, tokens, and session identifiers to interception.
- **XSS remains a high-risk category**, reflecting Juice Shop’s intentionally vulnerable nature and lack of client-side/output sanitization guarantees.
- **Missing authentication and MFA controls** between internal components increase lateral movement and privilege abuse risks.
- **CSRF risks** are very likely due to browser-based interactions without strong CSRF token enforcement.
- Several medium/low risks (missing vault, missing hardening, missing WAF) indicate absent defense-in-depth controls rather than direct vulnerabilities.

Overall, the baseline posture reflects a deliberately insecure application with minimal transport and storage protections.

---

### 1.4 Baseline Artifacts

Generated in `labs/lab2/baseline/`:

- `report.pdf` — full threat modeling report (including diagrams)
- Data Flow Diagram (PNG)
- Data Asset Diagram (PNG)
- `risks.json`
- `stats.json`
- `technical-assets.json`

---

## Task 2 — Secure HTTPS Variant & Risk Comparison

### 2.1 Risk Category Delta Table

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

---

### 2.2 Delta Analysis

**Specific changes made to the model**

A secure variant of the model was created in  
`labs/lab2/threagile-model.secure.yaml` with the following changes:

1. **User Browser → Application**
   - Protocol changed from `http` to `https`

2. **Reverse Proxy → Application**
   - Protocol changed from `http` to `https`

3. **Persistent Storage**
   - Encryption set to `transparent`

No architectural components were removed or renamed to ensure accurate diffs.

**Observed improvements:**

- All **unencrypted communication risks were eliminated** due to enforced HTTPS.
- One **unencrypted asset risk** was removed by enabling transparent encryption for persistent storage.

**Why other risks remain unchanged:**

- Application-layer vulnerabilities (XSS, CSRF, SSRF) are unaffected by transport encryption.
- Missing WAF, vault, identity store, and MFA are architectural/security control gaps not addressed by HTTPS alone.
- Juice Shop’s intentionally vulnerable design still drives many residual risks.

**Diagram comparison:**

- Data Flow Diagrams visually confirm encrypted communication paths in the secure variant.
- Asset diagrams reflect encrypted storage but unchanged trust boundaries.


