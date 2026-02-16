# Lab 2 — Threat Modeling with Threagile

## Task 1: Threagile Baseline Model & Risk Analysis

### Methodology
For risk ranking, I used the following composite score formula:
`Composite Score = (Severity * 100) + (Likelihood * 10) + Impact`

**Weights:**
- **Severity:** Critical (5), Elevated (4), High (3), Medium (2), Low (1)
- **Likelihood:** Very-likely (4), Likely (3), Possible (2), Unlikely (1)
- **Impact:** High (3), Medium (2), Low (1)

### Top 5 Risks Identified (Baseline)

Based on the generated baseline analysis:

| Rank | Severity | Category | Asset | Likelihood | Impact | Score |
|:---:|:---:|---|---|---|---|:---:|
| 1 | **Critical** | **Unencrypted Communication** | User Browser -> Juice Shop | Likely | High | **533** |
| 2 | **High** | **Unencrypted Asset** | Persistent Storage | Likely | High | **333** |
| 3 | **High** | **Missing Authentication** | Reverse Proxy -> Juice Shop | Likely | High | **333** |
| 4 | **High** | **Server-Side Request Forgery** | Juice Shop Application | Likely | Medium | **332** |
| 5 | **Medium** | **Cross-Site Scripting (XSS)** | Juice Shop Application | Likely | Medium | **232** |

*(Note: The score for Risk #1 is calculated as: 5 * 100 + 3 * 10 + 3 = 533)*

### Analysis of Critical Findings
1.  **Unencrypted Communication (HTTP):** The baseline model explicitly permits HTTP traffic on port 3000 directly to the application. This allows attackers on the network to sniff credentials (session tokens) or inject malicious scripts.
2.  **Unencrypted Data at Rest:** The `Persistent Storage` volume stores the database and logs without encryption (`encryption: none`). If the host machine is compromised, sensitive data is readable.
3.  **Missing Authentication:** The link between the Reverse Proxy and the App assumes trust without re-verifying identity, creating a risk if the internal network is breached.

### Diagrams (Baseline)
> *Generated diagrams representing the insecure baseline state.*

**Data Flow Diagram:**
![DFD](../labs/lab2/baseline/data-flow-diagram.png)

---

## Task 2: HTTPS Variant & Risk Comparison

### Delta Run Explanation

To improve the security posture, was created a `secure` variant of the model with the following hardening measures:

1.  **Enforced HTTPS everywhere:**
    - Changed `User Browser -> Direct to App` link to `protocol: https`.
    - Changed `Reverse Proxy -> To App` link to `protocol: https`.
2.  **Data-at-Rest Encryption:**
    - Updated `Persistent Storage` to use `encryption: transparent`.


#### Observed Results & Analysis
The automated risk analysis confirms that these changes directly reduced the threat landscape:

*   **Unencrypted Communication (Δ -2):**
    *   **Result:** The risk count dropped from 2 to 0.
    *   **Why:** Threagile no longer flags the communication links as vulnerable to sniffing or Man-in-the-Middle (MITM) attacks because the `protocol` is now set to `https`. This ensures confidentiality and integrity of data in transit (session tokens, product data).
*   **Unencrypted Asset (Δ -1):**
    *   **Result:** The risk count dropped from 2 to 1.
    *   **Why:** The `Persistent Storage` asset is now marked as `encrypted: transparent`. This mitigates physical security risks (e.g., stolen hard drives) and improper disposal risks, ensuring that the database and logs stored on the volume are not readable without the decryption key.


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

### Diagram Comparison
In the secure model's Data Flow Diagram, the edges connecting the Browser and the Proxy to the App are now dotted (indicating encrypted transport), and the storage asset is marked as encrypted.

**Secure Data Flow Diagram:**
![DFD Secure](../labs/lab2/secure/data-flow-diagram.png)