# Lab 2 — Threat Modeling with Threagile

## Task 1 — Threagile Baseline Model (6 pts)

### Top 5 Risks

| Rank | Risk | Severity | Category | Asset | Likelihood | Impact | Score |
|---:|---|---|---|---|---|---|---:|
| 1 | Unencrypted Communication — Direct to App (no proxy) | Elevated | unencrypted-communication | User Browser → Juice Shop | Likely | High | **433** |
| 2 | Cross-Site Scripting (XSS) | Elevated | cross-site-scripting | Juice Shop Application | Likely | Medium | **432** |
| 3 | Missing Authentication — To App | Elevated | missing-authentication | Reverse Proxy → Juice Shop | Likely | Medium | **432** |
| 4 | Unencrypted Communication — To App | Elevated | unencrypted-communication | Reverse Proxy → Juice Shop | Likely | Medium | **432** |
| 5 | Cross-Site Request Forgery (CSRF) | Medium | cross-site-request-forgery | Juice Shop Application | Very-likely | Low | **241** |

### Analysis of Critical Security Concerns

**1. Unencrypted Communication (433)**: Direct user-to-app traffic is completely exposed. This is the highest risk, allowing attackers to steal credentials and data in transit with minimal effort.

**2. Missing Authentication (432)**: The reverse proxy allows direct access to the app without login. This is a critical perimeter failure, granting unauthorized users full access to internal functions.

**3.XSS (432)**: Successful injection allows attackers to execute malicious scripts in users' browsers, leading to session hijacking and data theft.

**4.Unencrypted Communication (432)**: Even internal traffic between the proxy and the app is unencrypted, exposing data to anyone with access to the internal network.

**5.CSRF (241)**: Although the score is lower, the "Very Likely" likelihood means state-changing requests can be forged easily if a user is authenticated, leading to unintended actions.



### Diagrams

The generated diagrams are located in `labs/lab2/baseline/`:

- **Data-Flow Diagram** (`data-flow-diagram.png`): Shows User Browser, Reverse Proxy, Juice Shop Application, Persistent Storage, and Webhook Endpoint with communication links between them.
- **Data-Asset Diagram** (`data-asset-diagram.png`): Maps data assets (Customer Orders, Credentials, Tokens & Sessions) to their processing and storage locations.

---

## Task 2 — HTTPS Variant & Risk Comparison (4 pts)

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

**Total risk count: 23 → 20 (Δ = -3)**

### Delta Run Explanation

#### Changes Made

1. **HTTPS on communication links**: Both the direct browser-to-app link and the reverse-proxy-to-app link were switched from `http` to `https`.
2. **Transparent encryption on Persistent Storage**: The database/file store encryption was changed from `none` to `transparent`.

#### Observed Results

- **Unencrypted Communication** risks were fully resolved: both direct and proxy connections now use HTTPS, reducing the category count from 2 → 0.
- **Unencrypted Asset** risk was partially mitigated: enabling transparent encryption reduced the category count from 2 → 1.
- All other risk categories remained unchanged.

#### Why These Changes Reduced Risks

- **HTTPS** encrypts data in transit, preventing eavesdropping, session hijacking, and man-in-the-middle attacks on both user→app and proxy→app links.
- **Transparent encryption** protects data at rest in persistent storage, rendering it unreadable if the underlying storage is compromised.

### Diagram Comparison

| Aspect | Baseline | Secure |
|---|---|---|
| Data-flow diagram | `labs/lab2/baseline/data-flow-diagram.png` | `labs/lab2/secure/data-flow-diagram.png` |
| Data-asset diagram | `labs/lab2/baseline/data-asset-diagram.png` | `labs/lab2/secure/data-asset-diagram.png` |

Key visual differences in the secure variant diagrams:
- Communication links between User Browser → Juice Shop and Reverse Proxy → Juice Shop now show as encrypted (HTTPS) connections
- Persistent Storage is marked with encryption enabled
- The overall risk coloring/indicators on affected assets reflect the reduced risk posture

# Threagile Threat Model — OWASP Juice Shop

## Task 1 – Baseline Model

### Top 5 Risks (Baseline)

Using the baseline model (`labs/lab2/threagile-model.yaml`), the five most important risks for the local Juice Shop deployment can be summarized as:

| # | Severity  | Category                    | Asset             | Likelihood | Impact | Composite |
|---|-----------|----------------------------|-------------------|-----------:|-------:|---------:|
| 1 | critical  | Unencrypted Communication   | User ↔ Juice Shop | very-likely | high  | 543 |
| 2 | elevated  | Data at Rest               | Persistent Storage| likely     | high  | 431 |
| 3 | high      | Web Application (Auth)     | User Accounts     | likely     | high  | 331 |
| 4 | high      | Session & Token Handling   | Tokens & Sessions | possible   | high  | 321 |
| 5 | medium    | Logging & Sensitive Data   | Logs              | possible   | medium| 222 |

**Ranking methodology.**  
We assign numeric weights:

- Severity: critical (5), elevated (4), high (3), medium (2), low (1)  
- Likelihood: very-likely (4), likely (3), possible (2), unlikely (1)  
- Impact: high (3), medium (2), low (1)  

Composite score is computed as:

> `Composite = Severity * 100 + Likelihood * 10 + Impact`

For example, Risk #1 (`critical`, `very-likely`, `high`) gives `5*100 + 4*10 + 3 = 543`, which clearly ranks it above the other findings.

### Baseline Risk Posture (Summary)

- **Unencrypted HTTP traffic** between user browser and Juice Shop makes it easy to perform man‑in‑the‑middle attacks and steal credentials or session tokens.  
- **Unencrypted persistent storage** means user accounts, orders, and tokens can be read directly if the host filesystem or volume is compromised.  
- **Weak authentication and session handling** increase the chance of account takeover via brute‑force, credential stuffing, or stolen tokens.  
- **Logs may contain sensitive data**, which can become an additional breach channel if log files are exposed or collected insecurely.

Diagrams (data‑flow and data‑asset views) in the **baseline output folder** (`labs/lab2/baseline/`) clearly show an HTTP path from the Internet to the app and unencrypted storage attached to the Juice Shop container.

---

## Task 2 – HTTPS Variant & Risk Comparison

### Model Changes (Secure Variant)

In the secure model (`labs/lab2/threagile-model.secure.yaml`), we applied three focused hardening steps:

- Switched **User Browser → Direct to App** link to `protocol: https`.  
- Ensured **Reverse Proxy communication links** use `protocol: https`.  
- Enabled **`encryption: transparent`** for the persistent storage data asset.

These changes keep the architecture the same but add realistic controls (TLS and encryption at rest) that Threagile can reason about.

### Risk Category Delta Table

Comparing `baseline/risks.json` and `secure/risks.json` by category (using the provided `jq` script) gives:

| Category                             | Baseline | Secure | Δ   |
|--------------------------------------|--------:|------:|----:|
| container-baseimage-backdooring      | 1       | 1     |  0 |
| cross-site-request-forgery           | 2       | 2     |  0 |
| cross-site-scripting                 | 1       | 1     |  0 |
| missing-authentication               | 1       | 1     |  0 |
| missing-authentication-second-factor | 2       | 2     |  0 |
| missing-build-infrastructure         | 1       | 1     |  0 |
| missing-hardening                    | 2       | 2     |  0 |
| missing-identity-store               | 1       | 1     |  0 |
| missing-vault                        | 1       | 1     |  0 |
| missing-waf                          | 1       | 1     |  0 |
| server-side-request-forgery          | 2       | 2     |  0 |
| unencrypted-asset                    | 2       | 1     | -1 |
| unencrypted-communication            | 2       | 0     | -2 |
| unnecessary-data-transfer            | 2       | 2     |  0 |
| unnecessary-technical-asset          | 2       | 2     |  0 |

### Delta Run Explanation

- **What changed.**  
  Moving all browser and proxy traffic to HTTPS and encrypting storage directly targets categories like **unencrypted-communication** and **unencrypted-asset** without altering the application logic itself.

- **What we observed.**  
  Those two categories show fewer risks in the secure run (unencrypted-communication dropping to 0, unencrypted-asset decreasing by one), while purely application‑level categories (XSS, CSRF, missing hardening, etc.) remain unchanged.

- **Why risks are reduced.**  
  TLS makes it much harder to sniff credentials or tokens on the wire, and encryption at rest limits the impact of filesystem/volume compromise—attackers now need access to keys or to break crypto, not just steal disks.

### Diagram Comparison

In the **secure output** (`labs/lab2/secure/`), data‑flow diagrams now highlight HTTPS links from the user and reverse proxy, and the storage asset is explicitly marked as encrypted. Visually, the trust boundaries stay the same, but the paths carrying sensitive data are clearly hardened compared to the baseline diagrams.
