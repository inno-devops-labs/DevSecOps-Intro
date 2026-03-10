# Lab 2 Submission — Threat Modeling with Threagile (OWASP Juice Shop)

## Task 1 — Threagile Baseline Model

### 1.1 Baseline Generation & Artifacts

- **Model used:** `labs/lab2/threagile-model.yaml`
- **Command:**

```bash
mkdir -p labs/lab2/baseline labs/lab2/secure

docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

- **Generated artifacts in `labs/lab2/baseline/`:**
  - `report.pdf` — full report including diagrams
  - PNG diagrams: data-flow, data-asset
  - JSON exports: `risks.json`, `stats.json`, `technical-assets.json`

### 1.2 Risk Ranking Methodology

I used the formula provided in the lab:

- **Severity:** critical = 5, elevated = 4, high = 3, medium = 2, low = 1
- **Likelihood:** very-likely = 4, likely = 3, possible = 2, unlikely = 1
- **Impact:** high = 3, medium = 2, low = 1
- **Composite score:**  
  \[
  \text{Score} = \text{Severity} \times 100 + \text{Likelihood} \times 10 + \text{Impact}
  \]

To calculate the top 5 risks I used `jq`:

```bash
jq -r '[.[] | {title, category, technical_asset, severity, likelihood, impact}
  | . + {
      sev:(.severity | if .=="critical" then 5 elif .=="elevated" then 4 elif .=="high" then 3 elif .=="medium" then 2 else 1 end),
      lik:(.likelihood | if .=="very-likely" then 4 elif .=="likely" then 3 elif .=="possible" then 2 else 1 end),
      imp:(.impact | if .=="high" then 3 elif .=="medium" then 2 else 1 end)
    }
  | . + {score:(.sev*100 + .lik*10 + .imp)}]
  | sort_by(-.score) | .[0:5]
  | ("title|category|asset|severity|likelihood|impact|score"),
    ("-----|--------|-----|--------|----------|------|-----"),
    (.[] | "\(.title)|\(.category)|\(.technical_asset)|\(.severity)|\(.likelihood)|\(.impact)|\(.score)")' \
  labs/lab2/baseline/risks.json
```

### 1.3 Top 5 Risks (Baseline)

| title | category | asset | severity | likelihood | impact | score |
| ----- | -------- | ----- | -------- | ---------- | ------ | ----- |
| `<b>Unencrypted Communication</b> named <b>Direct to App (no proxy)</b> between <b>User Browser</b> and <b>Juice Shop Application</b> transferring authentication data (like credentials, token, session-id, etc.)` | unencrypted-communication | null | elevated | null | null | 411 |
| `<b>Unencrypted Communication</b> named <b>To App</b> between <b>Reverse Proxy</b> and <b>Juice Shop Application</b>` | unencrypted-communication | null | elevated | null | null | 411 |
| `<b>Cross-Site Scripting (XSS)</b> risk at <b>Juice Shop Application</b>` | cross-site-scripting | null | elevated | null | null | 411 |
| `<b>Missing Authentication</b> covering communication link <b>To App</b> from <b>Reverse Proxy</b> to <b>Juice Shop Application</b>` | missing-authentication | null | elevated | null | null | 411 |
| `<b>Missing Build Infrastructure</b> in the threat model (referencing asset <b>Juice Shop Application</b> as an example)` | missing-build-infrastructure | null | medium | null | null | 211 |

> **Note:** In the current Threagile output, the detailed `likelihood` and `impact` fields for these risks are not populated, so the resulting score is effectively driven by the mapped severity value. In manual analysis I treat them as at least `possible` and `medium` impact based on the application context (see below).

### 1.4 Analysis of Key Risks

- **Unencrypted Communication (Direct to App, Reverse Proxy → App):**  
  Lack of encryption for authentication data in transit exposes credentials and tokens to interception on the network (MITM, local network, malware). For a training environment this is acceptable, but in production all channels carrying tokens/sessions must be protected with HTTPS and HSTS.

- **Cross-Site Scripting (XSS) in Juice Shop:**  
  Juice Shop is intentionally vulnerable to XSS; this enables session theft, actions on behalf of victims, and UI tampering. In a real e‑commerce system this would be one of the most critical risks.

- **Missing Authentication (internal Reverse Proxy → App link):**  
  The absence of authentication on this internal hop makes lateral movement easier: if an attacker compromises the proxy or network, they can talk to the app directly. Typical compensating controls are mTLS or service‑level API keys between components.

- **Missing Build Infrastructure:**  
  Not modeling CI/CD infrastructure hides an entire class of supply‑chain risks (pipeline compromise, malicious images). For a DevSecOps lab this is an important reminder that we must protect not only runtime but also build and delivery.

### 1.5 Diagrams

- **Data Flow Diagram:** auto‑generated in `labs/lab2/baseline/` and showing the main flows: browser → (optional) reverse proxy → Juice Shop → persistent storage / WebHook.
- **Data Asset Diagram:** highlights that sensitive data (accounts, orders, tokens) converges in `Juice Shop Application` and `Persistent Storage`, making them primary attack targets.

---

## Task 2 — HTTPS Variant & Risk Comparison

### 2.1 Secure Model Variant

- **Model:** `labs/lab2/threagile-model.secure.yaml`
- **Key changes compared to the baseline:**
  - `User Browser → communication_links → Direct to App (no proxy)`: `protocol: https`
  - `Reverse Proxy → communication_links → To App`: `protocol: https`
  - `Persistent Storage`: `encryption: transparent`

### 2.2 Secure Variant Report Generation

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

The `labs/lab2/secure/` directory contains the same artifact types: `report.pdf`, PNG diagrams, and JSON risk exports.

### 2.3 Risk Category Delta Table

To compare risk categories I used the command from the lab:

```bash
jq -n \
  --slurpfile b labs/lab2/baseline/risks.json \
  --slurpfile s labs/lab2/secure/risks.json '
def tally(x):
  (x | group_by(.category) | map({ (.[0].category): length }) | add) // {};
  (tally($b[0])) as $B |
  (tally($s[0])) as $S |
  (($B + $S) | keys | sort) as $cats |
  [
    "| Category | Baseline | Secure | Δ |",
    "|---|---:|---:|---:|"
  ] + (
    $cats | map(
      "| " + . + " | " +
      (($B[.] // 0) | tostring) + " | " +
      (($S[.] // 0) | tostring) + " | " +
      (((($S[.] // 0) - ($B[.] // 0))) | tostring) + " |"
    )
  ) | .[]'
```

**Resulting category table:**

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

### 2.4 Delta Run Explanation

- **What changed in the model:**
  - All user‑facing channels were switched to **HTTPS** (both direct access to the app and traffic via the reverse proxy).
  - Internal traffic `Reverse Proxy → Juice Shop Application` was also switched to **HTTPS**, eliminating an unencrypted segment inside the host/container network.
  - `Persistent Storage` is now modeled with **`encryption: transparent`**, representing disk/volume encryption.

- **How this affected risks:**
  - Category **`unencrypted-communication`** dropped from 2 risks to 0 (`Δ = -2`):  
    these two risks were in the baseline top‑5 (unencrypted Direct to App and Reverse Proxy → App links). After switching the protocol to HTTPS Threagile no longer reports them.
  - Category **`unencrypted-asset`** decreased by one risk (`Δ = -1`), because encrypted persistent storage mitigates some threats tied to disk/volume compromise.
  - Other categories (XSS, CSRF, missing‑*, etc.) remain unchanged, because enabling TLS and disk encryption does not fix application logic flaws or process/organizational gaps.

- **Security interpretation:**
  - **HTTPS + disk encryption** significantly improve protection **in transit** and **at rest**, but do not replace secure coding, testing, and hardening of the application itself.
  - OWASP Top 10‑style issues (XSS, CSRF, broken auth) are still present and must be addressed by other measures (input validation, contextual output encoding, strict session management, security headers).
  - Threagile clearly illustrates that “just adding TLS” is important but not sufficient: once cryptographic risks are reduced, logical and process risks remain prominent.

### 2.5 Diagram Comparison

- On the **data‑flow diagram** all user traffic arrows are now labeled HTTPS, including the internal path through the reverse proxy; this reflects the removal of passive sniffing opportunities.
- On the **data‑asset diagram** the storage status changed: the persistent volume is marked as encrypted, which reduces blast radius if the host or disk is compromised.

---

## Summary

- A baseline threat model for the local OWASP Juice Shop deployment was created and Threagile artifacts were generated automatically.
- A formal prioritization (composite score) was performed and key risks around unencrypted traffic, XSS, and missing auth/hardening were identified.
- A secure model variant with HTTPS everywhere and encrypted persistent storage was created, demonstrating reduced `unencrypted-communication` and `unencrypted-asset` categories.
- All commands and results are documented in `labs/submission2.md` for reproducibility.

