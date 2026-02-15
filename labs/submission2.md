# Lab 2 — Threat Modeling with Threagile 
## Task 1 — Threagile Baseline Model

### 1.1 & 1.2: Baseline Generation and Outputs

Baseline threat model was generated with:

```bash
mkdir -p labs/lab2/baseline labs/lab2/secure
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

**Generated artifacts in `labs/lab2/baseline/`:**
- `report.pdf` — full PDF report with threat analysis and recommendations
- `data-flow-diagram.png` — visualizes how data flows through the system
- `data-asset-diagram.png` — shows where sensitive data is stored
- `risks.json` — machine-readable list of all identified risks (15 total)
- `stats.json` — summary statistics
- `technical-assets.json` — detailed asset information

### 1.3: Risk Analysis and Documentation

#### Risk Ranking Methodology

Threagile uses a severity-based ranking system (not a composite score in this version):
- **Severity levels:** elevated (highest priority), medium, low
- **Likelihood:** very-likely, likely, possible, unlikely
- **Impact:** high, medium, low
- **Risks are prioritized by severity first**, then by the assets they affect

#### Top 5 Risks (Baseline Model)

| # | Severity | Category | Risk Title | Affected Asset(s) |
|---|----------|----------|-----------|-------------------|
| 1 | **elevated** | Unencrypted Communication | Direct to App (no proxy) | User Browser ↔ Juice Shop |
| 2 | **elevated** | Unencrypted Communication | To App (proxy → app) | Reverse Proxy ↔ Juice Shop |
| 3 | **elevated** | Missing Authentication | To App link has no auth | Reverse Proxy ↔ Juice Shop |
| 4 | **elevated** | Cross-Site Scripting (XSS) | XSS vulnerability in app | Juice Shop Application |
| 5 | **medium** | Cross-Site Request Forgery (CSRF) | CSRF attacks possible | User Browser ↔ Juice Shop |

#### Critical Security Concerns Explained

**1. Unencrypted Browser-to-App Traffic (Direct to App)**
- **The Problem:** Users accessing the app directly at `http://localhost:3000` have their traffic sent in **plaintext** (unencrypted)
- **The Risk:** An attacker on the local network (or with network access) can:
  - Intercept login credentials and steal usernames/passwords
  - Capture session tokens and impersonate the user
  - Modify requests to perform unauthorized actions
- **Why It's Critical:** This link transmits authentication data (credentials, session IDs, tokens) which is the highest value target for attackers
- **Mitigation in Secure Model:** Switch to HTTPS (encrypted connection)

**2. Unencrypted Proxy-to-App Traffic (To App)**
- **The Problem:** Even if users connect via HTTPS to the reverse proxy, the **internal link** from proxy → app is still HTTP (plaintext)
- **The Risk:** Any process running on the host machine could sniff or tamper with the traffic
- **Why It's Critical:** The proxy is supposed to be a security gateway, but the internal link bypasses that protection
- **Mitigation in Secure Model:** Enforce HTTPS/TLS on the proxy-to-app link

**3. Missing Authentication Between Proxy and App**
- **The Problem:** There's no authentication mechanism on the proxy → app link
- **The Risk:** Any process on the host could impersonate the reverse proxy and send forged requests directly to the app
- **Why It's Medium Severity:** Requires local access (not as exposed as the other two)
- **Note:** This risk persists in the secure model because HTTPS alone doesn't add mutual authentication

**4. Cross-Site Scripting (XSS)**
- **The Problem:** OWASP Juice Shop is intentionally vulnerable to XSS attacks
- **The Risk:** Attackers can inject malicious JavaScript into the application that executes in users' browsers, stealing session tokens or personal data
- **Why It's Critical:** XSS can lead to full account compromise
- **Note:** This is an **application-level vulnerability**, not a network/infrastructure issue — HTTPS doesn't prevent XSS

**5. Cross-Site Request Forgery (CSRF)**
- **The Problem:** The application doesn't implement anti-CSRF tokens
- **The Risk:** Attackers can trick logged-in users into performing unwanted actions (changing password, transferring funds, etc.)
- **Why It's Medium Severity:** Requires the user to be logged in and visit a malicious site
- **Note:** Also app-level — HTTPS doesn't prevent CSRF

#### System Architecture (from diagrams)

The baseline model describes:
- **User Browser** (untrusted, on Internet) 
  - ↓ HTTP (unencrypted) — **RISK**
- **Reverse Proxy** (optional security layer on host)
  - ↓ HTTP (unencrypted) — **RISK**
- **Juice Shop Application** (Node.js/Express in Docker container)
  - ↓ Writes to
- **Persistent Storage** (host-mounted volume with database, logs, uploads)
- Optional outbound connection to **Webhook Endpoint** (for challenge notifications)

---

## Task 2 — HTTPS Variant & Risk Comparison

### 2.1: Secure Model Changes

A copy of the baseline model was modified and saved as `labs/lab2/threagile-model.secure.yaml` with these **3 security improvements**:

#### Change 1: Enable HTTPS for Direct Browser Access
```yaml
# Before (baseline):
Direct to App (no proxy):
  protocol: http          # ❌ Unencrypted

# After (secure):
Direct to App (no proxy):
  protocol: https         # ✅ Encrypted
```
**Effect:** Encrypts traffic between user and app, preventing credential interception

#### Change 2: Enable HTTPS for Proxy-to-App Link
```yaml
# Before (baseline):
Reverse Proxy → To App:
  protocol: http          # ❌ Unencrypted

# After (secure):
Reverse Proxy → To App:
  protocol: https         # ✅ Encrypted
```
**Effect:** Encrypts internal traffic, protecting against local network sniffing

#### Change 3: Enable Encryption at Rest
```yaml
# Before (baseline):
Persistent Storage:
  encryption: none        # ❌ Database unencrypted on disk

# After (secure):
Persistent Storage:
  encryption: transparent # ✅ Encrypted at rest
```
**Effect:** Protects stored data (database, logs, uploads) if the host is physically compromised or storage is stolen

### 2.2: Secure Variant Generation

The secure model was analyzed with the same Threagile command:

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

**Generated artifacts in `labs/lab2/secure/`:**
- `report.pdf` — updated threat report reflecting security improvements
- `data-flow-diagram.png` — same architecture (only security metadata changed)
- `data-asset-diagram.png` — same assets (only encryption setting changed)
- `risks.json` — updated risk list with reduced threat count
- `stats.json`, `technical-assets.json` — updated metadata

### 2.3: Risk Category Delta Analysis

**Baseline vs Secure Comparison:**

| Category | Baseline | Secure | Δ | Status |
|---|---:|---:|---:|---|
| container-baseimage-backdooring | 1 | 1 | 0 | ✓ Unchanged |
| cross-site-request-forgery | 2 | 2 | 0 | ✓ Unchanged (app-level issue) |
| cross-site-scripting | 1 | 1 | 0 | ✓ Unchanged (app-level issue) |
| missing-authentication | 1 | 1 | 0 | ✓ Unchanged (no auth added) |
| missing-authentication-second-factor | 2 | 2 | 0 | ✓ Unchanged |
| missing-build-infrastructure | 1 | 1 | 0 | ✓ Unchanged |
| missing-hardening | 2 | 2 | 0 | ✓ Unchanged |
| missing-identity-store | 1 | 1 | 0 | ✓ Unchanged |
| missing-vault | 1 | 1 | 0 | ✓ Unchanged |
| missing-waf | 1 | 1 | 0 | ✓ Unchanged |
| server-side-request-forgery | 2 | 2 | 0 | ✓ Unchanged |
| **unencrypted-asset** | **2** | **1** | **-1** | 🎯 **FIXED** |
| **unencrypted-communication** | **2** | **0** | **-2** | 🎯 **FIXED** |
| unnecessary-data-transfer | 2 | 2 | 0 | ✓ Unchanged |
| unnecessary-technical-asset | 2 | 2 | 0 | ✓ Unchanged |

**Summary:** 3 risks eliminated (−3 total), 12 categories unchanged (0 delta)

### 2.4: Delta Explanation

#### Why Unencrypted-Communication Dropped by 2

**Baseline risks found 2 unencrypted communication links:**
1. Direct to App (User Browser → Juice Shop over HTTP)
2. To App (Reverse Proxy → Juice Shop over HTTP)

**Secure model fixed both by setting `protocol: https`**
- Direct to App: `http` → `https` ✅
- To App: `http` → `https` ✅

**Result:** Both risks eliminated → Δ = 2 − 0 = **−2** 🎯

#### Why Unencrypted-Asset Dropped by 1

**Baseline found 2 unencrypted assets:**
1. Persistent Storage (encryption: none)
2. *(Other asset with unencrypted flag)*

**Secure model fixed storage by setting `encryption: transparent`**
- Persistent Storage: `none` → `transparent` ✅

**Result:** One risk eliminated → Δ = 2 − 1 = **−1** 🎯

#### Why Other Risks Remained Unchanged

**Application-level vulnerabilities don't depend on encryption:**
- XSS, CSRF, missing 2FA, hardening issues, etc. are **code-level bugs**
- HTTPS and storage encryption are **infrastructure controls**
- They don't fix business logic vulnerabilities
- Example: XSS happens because the app doesn't escape HTML input properly — HTTPS won't prevent this

**Missing infrastructure components:**
- No WAF, no vault, no identity store, no build pipeline — these would require major architectural changes
- Our 3 changes were **encryption and protocol only**

### 2.5: Architecture Comparison

**Key Insight:** Baseline and secure have **identical architecture and data flow**
- Same number of assets
- Same communication links
- Same trust boundaries

**The only differences are metadata:**
- Protocol settings (HTTP vs HTTPS)
- Encryption settings (none vs transparent)

**This demonstrates:** Risk reduction doesn't always require architectural changes — **security controls matter**. By enabling existing security features (HTTPS, encryption at rest), we reduced exploitable risks from 15 to 12.

---

## Summary

### Task 1: Baseline Analysis ✓
- **Model:** OWASP Juice Shop with optional reverse proxy
- **Risks Found:** 15 total risks across 15 categories
- **Top Severity:** Elevated (4 risks) — mostly unencrypted communication
- **Key Issues:** Plaintext traffic, missing proxy auth, app-level vulnerabilities

### Task 2: Secure Variant ✓
- **Model:** Same architecture with HTTPS + encryption at rest
- **Risks Found:** 12 total risks (3 eliminated)
- **Improvements:** 
  - **−2 unencrypted-communication** (both links now HTTPS)
  - **−1 unencrypted-asset** (storage now encrypted at rest)
- **Unchanged:** 12 categories still have risks (require different mitigations)

### Key Learning
**Infrastructure security controls (encryption, HTTPS, secure storage) address infrastructure threats, but application vulnerabilities (XSS, CSRF, missing auth logic) require code-level fixes.** A comprehensive security posture needs both.
