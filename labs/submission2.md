# Lab 2 Submission — Threat Modeling with Threagile


## Task 1 — Baseline Threat Model

### 1.1 Generate baseline outputs (command used)

```bash
mkdir -p labs/lab2/baseline labs/lab2/secure

docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 1.2 Baseline outputs 

All files are present in `labs/lab2/baseline/`:

- **Report**: `labs/lab2/baseline/report.pdf`
- **Diagrams**: `labs/lab2/data-asset-diagram.png` and `labs/lab2/data-flow-diagram.png`
- **Risk exports**:
  - `labs/lab2/baseline/risks.json`
  - `labs/lab2/baseline/stats.json`
  - `labs/lab2/baseline/technical-assets.json`

### 1.2.1 Baseline summary (from Threagile outputs)

- **Total risks**: 23
- **By severity**:
  - elevated: 4
  - medium: 14
  - low: 5
- **Risk categories**: 15 (per `labs/lab2/baseline/report.pdf`, “Impact Analysis … in 15 Categories”)

### 1.3 Risk ranking methodology (composite score)

Weights (per lab instructions):

- **Severity**: critical=5, elevated=4, high=3, medium=2, low=1
- **Likelihood**: very-likely=4, likely=3, possible=2, unlikely=1
- **Impact**: high=3, medium=2, low=1

Composite score:

\[
\text{Composite} = (\text{Severity}\times 100) + (\text{Likelihood}\times 10) + (\text{Impact})
\]

Example:

- elevated + likely + high → \(4\times 100 + 3\times 10 + 3 = 433\)

### 1.4 Top 5 risks (baseline)

| Rank | Composite | Severity | Likelihood | Impact | Category | Asset |
|---:|---:|---|---|---|---|---|
| 1 | 433 | elevated | likely | high | unencrypted-communication | User Browser |
| 2 | 432 | elevated | likely | medium | cross-site-scripting | Juice Shop Application |
| 3 | 432 | elevated | likely | medium | missing-authentication | Juice Shop Application |
| 4 | 432 | elevated | likely | medium | unencrypted-communication | Reverse Proxy |
| 5 | 241 | medium | very-likely | low | cross-site-request-forgery | Juice Shop Application |

Notes (how to interpret the top risks):

- **Unencrypted communication (Browser → App direct)**: risk of credential/session/token interception on plaintext HTTP. This is particularly relevant even on “local” setups if ports are exposed beyond loopback or if traffic traverses untrusted segments (e.g., Wi‑Fi, corporate proxies, VM bridges).
- **XSS (Juice Shop)**: client-side code execution leading to session theft, account takeover, and data exfiltration. Given Juice Shop is intentionally vulnerable, XSS appears as a high-priority baseline concern.
- **Missing authentication (Reverse Proxy → App)**: lack of authenticated service-to-service link or mTLS means internal link can be abused if an attacker gains access to the host/container network (or can impersonate the proxy).
- **CSRF**: high likelihood; can trigger unwanted state-changing actions when a victim is authenticated.


### 1.5 Diagrams (baseline)

Baseline diagrams (also see `labs/lab2/data-asset-diagram.png` and `labs/lab2/data-flow-diagram.png`):

![Baseline Data Asset Diagram](lab2/baseline/data-asset-diagram.png)

![Baseline Data Flow Diagram](lab2/baseline/data-flow-diagram.png)


---

## Task 2 — HTTPS Variant & Risk Comparison

### 2.1 Secure model changes made

Created `labs/lab2/threagile-model.secure.yaml` by copying the baseline model and applying exactly these lab-required changes:

- **User Browser → communication_links → Direct to App (no proxy)**: `protocol: https`
- **Reverse Proxy → communication_links → To App**: `protocol: https` 
- **Persistent Storage**: `encryption: transparent` 

### 2.2 Generate secure variant outputs (command used)

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 2.2.1 Secure summary (from Threagile outputs)

- **Total risks**: 20
- **By severity** (unchecked):
  - elevated: 2
  - medium: 13
  - low: 5
- **Risk categories**: 14 (per `labs/lab2/secure/report.pdf`, “Impact Analysis … in 14 Categories”)

### 2.3 Risk category delta table (baseline vs secure)

Generated using the lab-provided `jq` command:

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

Output:

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

### 2.4 Delta run explanation (why the risks changed)

- **What changed**
  - Switched plaintext HTTP links to **HTTPS** for:
    - Browser → App (direct)
    - Reverse Proxy → App
  - Enabled **transparent encryption** for the persistent storage volume.

- **Observed results**
  - `unencrypted-communication`: **2 → 0** (Δ = -2)
  - `unencrypted-asset`: **2 → 1** (Δ = -1)

- **Why those reductions happened**
  - Setting the two communication links to `protocol: https` removes Threagile findings about plaintext traffic for those links (no more “unencrypted communication” risks).
  - Setting persistent storage to `encryption: transparent` removes the “unencrypted technical asset” finding for the storage component.
  - The remaining `unencrypted-asset` risk is still present for **Juice Shop Application** because we did **not** change that asset’s `encryption` field in this task.

### 2.5 Diagram comparison (baseline vs secure)

Baseline diagrams (also see `labs/lab2/data-asset-diagram.png` and `labs/lab2/data-flow-diagram.png`):

![Baseline Data Asset Diagram](lab2/baseline/data-asset-diagram.png)

![Baseline Data Flow Diagram](lab2/baseline/data-flow-diagram.png)

And secure diagrams:

![Secure Data Asset Diagram](lab2/secure/data-asset-diagram.png)

![Secure Data Flow Diagram](lab2/secure/data-flow-diagram.png)

- **What changes you should see in the secure DFD (vs baseline)**
  - **Direct browser access** (“Direct to App (no proxy)”) is **HTTPS** (baseline model had this as HTTP).
  - **Reverse proxy → app hop** (“To App”) is **HTTPS** (baseline model had this as HTTP).
  - **Persistent Storage** is shown as **encrypted at rest** (because its `encryption` is `transparent` in the secure model).

- **What does not change**
  - Same technical data assets diagrams and assets/trust boundaries and overall architecture shape; only the security properties/labels change.
