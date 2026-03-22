# Threat Modeling with Threagile

## Baseline Threat Model (6 pts)

### Top 5 Risks by Composite Score
Using the provided formula **Composite = Severity * 100 + Likelihood * 10 + Impact** with the following mappings:

I extracted the top 5 risks from `labs/lab2/baseline/risks.json` (using the actual `exploitation_likelihood` and `exploitation_impact` fields). The results are:

| Risk Title | Severity | Category | Asset | Likelihood | Impact | Composite |
|------------|----------|----------|-------|------------|--------|-----------|
| **Unencrypted Communication** named **Direct to App (no proxy)** between **User Browser** and **Juice Shop Application** transferring authentication data | elevated | unencrypted-communication | user-browser → juice-shop | likely | high | 433 |
| **Unencrypted Communication** named **To App** between **Reverse Proxy** and **Juice Shop Application** | elevated | unencrypted-communication | reverse-proxy → juice-shop | likely | medium | 432 |
| **Cross‑Site Scripting (XSS)** risk at **Juice Shop Application** | elevated | cross-site-scripting | juice-shop | likely | medium | 432 |
| **Missing Authentication** covering communication link **To App** from **Reverse Proxy** to **Juice Shop Application** | elevated | missing-authentication | reverse-proxy → juice-shop | likely | medium | 432 |
| **Cross‑Site Request Forgery (CSRF)** risk at **Juice Shop Application** via **Direct to App (no proxy)** from **User Browser** | medium | cross-site-request-forgery | juice-shop | very‑likely | low | 241 |

### Analysis of Critical Security Concerns
The baseline model reveals several high‑priority risks inherent to the default Juice Shop deployment:

- **Unencrypted communication** on both direct browser‑to‑app and reverse‑proxy‑to‑app links exposes sensitive data (session tokens, credentials) to eavesdropping and man‑in‑the‑middle attacks on the local network.
- **Cross‑Site Scripting (XSS)** - the model correctly flags it, as the application stores and reflects user input without proper sanitisation.
- **Missing authentication** between the reverse proxy and the app means that if an attacker gains access to the internal container network, they could directly call the backend API without any checks.
- **Cross-Site Request Forgery** vulnerabilities allow attackers to trick authenticated users into performing unwanted actions, which is especially dangerous given the lack of anti‑CSRF tokens in the default setup.

The most critical issues are the lack of encryption and the XSS risk, both of which can lead to account compromise and data theft.

### Screenshots
**Baseline Data Flow Diagram**  
![Baseline DFD](lab2/baseline/data-flow-diagram.png)

**Baseline Data Assets Diagram**  
![Baseline Data Assets](lab2/baseline/data-asset-diagram.png)


## HTTPS Variant and Risk Comparison

### Risk Category Delta Table
Using the provided `jq` command to compare risk categories between baseline and secure I get this table:

**Resulting table:**

| Category | Baseline | Secure | Δ |
|:---|---:|---:|---:|
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
| **unencrypted-asset** | 2 | 1 | **-1** |
| **unencrypted-communication** | 2 | 0 | **-2** |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

### Delta Run Explanation
The changes made in the secure model directly impacted the risk categories:

- **unencrypted-communication** dropped from 2 to 0 because both communication links were switched to HTTPS. The two risks that originally flagged unencrypted traffic are now eliminated.
- **unencrypted-asset** decreased from 2 to 1 because the persistent storage now has `encryption: transparent`. One of the two risks related to unencrypted data at rest was reduced; the remaining risk involves the Juice Shop application itself (the app code and runtime memory), which cannot be fully encrypted without more fundamental changes.

All other categories remained unchanged, as they are unrelated to transport encryption or storage encryption (e.g., XSS, CSRF, missing authentication) – those vulnerabilities are inherent to the application and would require code‑level fixes or additional controls (for example input validation) to address.

This demonstrates that even simple configuration improvements (HTTPS, disk encryption) can effectively reduce the threat landscape. However, deeper application‑level risks persist and highlight the need for secure development practices.

### Screenshots
**Secure Data Flow Diagram**  
![Baseline DFD](lab2/secure/data-flow-diagram.png)


**Comparison:** The diagrams look identical except for the protocol labels on the communication links, which now show `https` instead of `http`. This visually confirms the model changes.
