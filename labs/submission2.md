# Lab 2 Submission — Threat Modeling with Threagile

## Student / Context
- Name: `Danil Fishchenko`
- Email: `ppepegaa@yandex.com`
- Target app: `bkimminich/juice-shop:v19.0.0`
- Baseline model: `labs/lab2/threagile-model.yaml`
- Secure model: `labs/lab2/threagile-model.secure.yaml`

## Task 1 — Baseline Threat Model

### 1.1 Baseline generation command
```bash
mkdir -p labs/lab2/baseline labs/lab2/secure

docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 1.2 Output verification
Generated files in `labs/lab2/baseline/`:
- `report.pdf`
- `data-flow-diagram.png`
- `data-asset-diagram.png`
- `risks.json`
- `stats.json`
- `technical-assets.json`

Risk totals from generated files:
- Total risks: `23`
- Severity split: `elevated=4`, `medium=14`, `low=5`

### 1.3 Risk ranking methodology
Composite scoring weights used exactly as requested:
- Severity: `critical=5`, `elevated=4`, `high=3`, `medium=2`, `low=1`
- Likelihood: `very-likely=4`, `likely=3`, `possible=2`, `unlikely=1`
- Impact: `high=3`, `medium=2`, `low=1`
- Composite formula: `Severity*100 + Likelihood*10 + Impact`

Examples:
- `unencrypted-communication (user-browser)`: `4*100 + 3*10 + 3 = 433`
- `cross-site-scripting (juice-shop)`: `4*100 + 3*10 + 2 = 432`

### Top 5 risks (baseline)
| Rank | Composite | Severity | Category | Asset | Likelihood | Impact |
|---:|---:|---|---|---|---|---|
| 1 | 433 | elevated | unencrypted-communication | user-browser | likely | high |
| 2 | 432 | elevated | cross-site-scripting | juice-shop | likely | medium |
| 3 | 432 | elevated | missing-authentication | juice-shop | likely | medium |
| 4 | 432 | elevated | unencrypted-communication | reverse-proxy | likely | medium |
| 5 | 241 | medium | cross-site-request-forgery | juice-shop | very-likely | low |

### Baseline risk analysis
Key security concerns from the highest-ranked findings:
- **Unencrypted communication** is the dominant risk driver (direct browser-to-app traffic and proxy-to-app link), exposing authentication/session material to interception or tampering.
- **Cross-site scripting** remains elevated in the application tier and can lead to credential/session theft and client-side compromise.
- **Missing authentication** on a backend-facing path indicates trust assumptions between components that could be abused if boundary controls fail.
- **Cross-site request forgery** appears with very-likely likelihood, indicating session-bearing browser interactions should be hardened with anti-CSRF controls.

### Diagram references (baseline)
- Data flow diagram: `labs/lab2/baseline/data-flow-diagram.png`
- Data asset diagram: `labs/lab2/baseline/data-asset-diagram.png`
- Full report: `labs/lab2/baseline/report.pdf`

## Task 2 — HTTPS Variant and Risk Comparison

### 2.1 Secure model changes applied
Created `labs/lab2/threagile-model.secure.yaml` from baseline and changed:
- `User Browser -> Direct to App (no proxy) -> protocol: https`
- `Reverse Proxy -> To App -> protocol: https`
- `Persistent Storage -> encryption: transparent`

### 2.2 Secure generation command
```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

Secure run totals:
- Total risks: `20`
- Severity split: `elevated=2`, `medium=13`, `low=5`

### 2.3 Risk category delta (Baseline vs Secure)
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

### Delta run explanation
Observed reductions directly match the control changes:
- `unencrypted-communication`: decreased by `-2` because both formerly HTTP links were switched to HTTPS.
- `unencrypted-asset`: decreased by `-1` because persistent storage encryption was changed to `transparent`.
- No new risks were introduced in the secure variant; removed risks correspond to the expected communication/storage encryption findings.

Interpretation:
- Transport encryption controls remove high-priority exposure of credentials/sessions in transit.
- Storage encryption reduces at-rest data exposure for the host-mounted volume.
- Remaining categories indicate additional controls are still needed (e.g., auth hardening, WAF, identity store, hardening, CI/build security).

### Diagram comparison references (baseline vs secure)
- Data-flow diagram (baseline): `labs/lab2/baseline/data-flow-diagram.png`
- Data-flow diagram (secure): `labs/lab2/secure/data-flow-diagram.png`
- Data-asset diagram (baseline): `labs/lab2/baseline/data-asset-diagram.png`
- Data-asset diagram (secure): `labs/lab2/secure/data-asset-diagram.png`

Generated diagram files differ between runs (different hashes/sizes), confirming model-driven layout/content updates.

## Command evidence used for delta table
```bash
jq -nr \
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
