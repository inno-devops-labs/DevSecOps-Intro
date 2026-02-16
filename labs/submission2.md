# Lab 2 Submission — Threat Modeling with Threagile

## Task 1 - Threagile Baseline Model

### 1.1 Generate Baseline Threat Model

Executed commands:

```bash
mkdir -p labs/lab2/baseline labs/lab2/secure
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 1.2 Verify Generated Outputs

Artifacts created in `labs/lab2/baseline/`:
- `report.pdf`
- `data-flow-diagram.png`
- `data-asset-diagram.png`
- `risks.json`
- `stats.json`
- `technical-assets.json`

Verification output:

```bash
$ ls -la labs/lab2/baseline
total 5088
drwxr-xr-x@ 8 a89088  staff      256 Feb 16 16:06 .
drwxr-xr-x@ 5 a89088  staff      160 Feb 16 16:06 ..
-rw-r--r--  1 a89088  staff   111869 Feb 16 16:07 data-asset-diagram.png
-rw-r--r--  1 a89088  staff   232261 Feb 16 16:07 data-flow-diagram.png
-rw-r--r--  1 a89088  staff  1310911 Feb 16 16:07 report.pdf
-rw-r--r--  1 a89088  staff    15848 Feb 16 16:07 risks.json
-rw-r--r--  1 a89088  staff      536 Feb 16 16:07 stats.json
-rw-r--r--  1 a89088  staff     5694 Feb 16 16:07 technical-assets.json
```

### 1.3 Risk Ranking Methodology

Scoring model:
- Severity: critical=5, elevated=4, high=3, medium=2, low=1
- Likelihood: very-likely=4, likely=3, possible=2, unlikely=1
- Impact: high=3, medium=2, low=1
- Composite score = `Severity*100 + Likelihood*10 + Impact`

Tie-breaking rule for equal scores: sort by category name and then by risk title for deterministic ranking.

### 1.4 Top 5 Risks (Baseline)

| Rank | Composite | Severity | Category | Asset | Likelihood | Impact |
|---:|---:|---|---|---|---|---|
| 1 | 433 | elevated | unencrypted-communication | user-browser | likely | high |
| 2 | 432 | elevated | cross-site-scripting | juice-shop | likely | medium |
| 3 | 432 | elevated | missing-authentication | juice-shop | likely | medium |
| 4 | 432 | elevated | unencrypted-communication | reverse-proxy | likely | medium |
| 5 | 241 | medium | cross-site-request-forgery | juice-shop | very-likely | low |

### 1.5 Baseline Risk Posture Analysis

Risk distribution from `stats.json`:
- elevated: 4
- medium: 14
- low: 5
- high: 0
- critical: 0

Key security concerns:
- The highest-ranked risk is unencrypted client-to-application communication carrying authentication data, which exposes credentials/tokens to interception.
- Unencrypted reverse-proxy to app traffic keeps sensitive internal traffic vulnerable to sniffing/tampering.
- Missing authentication on the reverse-proxy to app link indicates weak trust boundaries between components.
- XSS remains one of the top elevated risks and can be chained with session/token theft in browser-facing flows.
- CSRF appears as a high-likelihood medium-severity risk, suggesting request origin protections are insufficient.

### 1.6 Diagram References

- Data-flow diagram: `labs/lab2/baseline/data-flow-diagram.png`
- Data-asset diagram: `labs/lab2/baseline/data-asset-diagram.png`
- Full baseline report: `labs/lab2/baseline/report.pdf`

---

## Task 2 - HTTPS Variant and Risk Comparison

### 2.1 Create Secure Model Variant

Created `labs/lab2/threagile-model.secure.yaml` from baseline model with these changes:
- `User Browser -> communication_links -> Direct to App (no proxy) -> protocol: https`
- `Reverse Proxy -> communication_links -> To App -> protocol: https`
- `Persistent Storage -> encryption: transparent`

### 2.2 Generate Secure Variant Analysis

Executed command:

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

Artifacts created in `labs/lab2/secure/`:
- `report.pdf`
- `data-flow-diagram.png`
- `data-asset-diagram.png`
- `risks.json`
- `stats.json`
- `technical-assets.json`

Verification output:

```bash
$ ls -la labs/lab2/secure
total 3232
drwxr-xr-x@ 8 a89088  staff      256 Feb 16 16:18 .
drwxr-xr-x@ 6 a89088  staff      192 Feb 16 16:17 ..
-rw-r--r--  1 a89088  staff   112898 Feb 16 16:18 data-asset-diagram.png
-rw-r--r--  1 a89088  staff   233353 Feb 16 16:18 data-flow-diagram.png
-rw-r--r--  1 a89088  staff  1276729 Feb 16 16:18 report.pdf
-rw-r--r--  1 a89088  staff    13634 Feb 16 16:18 risks.json
-rw-r--r--  1 a89088  staff      536 Feb 16 16:18 stats.json
-rw-r--r--  1 a89088  staff     5692 Feb 16 16:18 technical-assets.json
```

### 2.3 Risk Category Delta Table

Used the provided `jq` command from the lab instructions to compare `baseline/risks.json` and `secure/risks.json`.

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

Specific model changes:
- Enforced HTTPS on direct browser-to-app link.
- Enforced HTTPS on reverse-proxy-to-app link.
- Enabled transparent encryption for persistent storage.

Observed impact:
- Total risks reduced from **23** (baseline) to **20** (secure).
- Elevated risks reduced from **4** to **2**.
- `unencrypted-communication` category reduced from **2** to **0**.
- `unencrypted-asset` category reduced from **2** to **1**.

Why these changes reduced risks:
- Switching both relevant communication links to HTTPS removes plaintext transport exposure for credentials/session data and internal proxy-app traffic, directly eliminating unencrypted communication findings.
- Enabling transparent storage encryption mitigates the unencrypted-at-rest issue for persistent storage, removing one unencrypted asset finding.
- Most other categories remain unchanged because they are driven by application security controls (e.g., XSS/CSRF/auth hardening) rather than transport/storage encryption settings.

### 2.5 Baseline vs Secure Diagram Comparison

- Baseline data-flow diagram: `labs/lab2/baseline/data-flow-diagram.png`
- Secure data-flow diagram: `labs/lab2/secure/data-flow-diagram.png`
- Baseline data-asset diagram: `labs/lab2/baseline/data-asset-diagram.png`
- Secure data-asset diagram: `labs/lab2/secure/data-asset-diagram.png`
- Baseline report: `labs/lab2/baseline/report.pdf`
- Secure report: `labs/lab2/secure/report.pdf`
