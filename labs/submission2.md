# Lab 2 - Threat Modeling with Threagile

## Task 1 - Threagile Baseline Model

### Baseline Generation

```bash
mkdir -p labs/lab2/baseline labs/lab2/secure
docker run --rm -v "${PWD}:/app/work" threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

### Generated Baseline Outputs
- `labs/lab2/baseline/report.pdf`
- `labs/lab2/baseline/data-flow-diagram.png`
- `labs/lab2/baseline/data-asset-diagram.png`
- `labs/lab2/baseline/risks.json`
- `labs/lab2/baseline/stats.json`
- `labs/lab2/baseline/technical-assets.json`

### Risk Ranking Methodology
- Severity weights: critical=5, elevated=4, high=3, medium=2, low=1
- Likelihood weights: very-likely=4, likely=3, possible=2, unlikely=1
- Impact weights: high=3, medium=2, low=1
- Composite score formula: `Severity*100 + Likelihood*10 + Impact`

### Top 5 Risks (Baseline)
| Rank | Composite Score | Severity | Category | Asset | Likelihood | Impact |
|---:|---:|---|---|---|---|---|
| 1 | 433 | elevated | unencrypted-communication | user-browser | likely | high |
| 2 | 432 | elevated | cross-site-scripting | juice-shop | likely | medium |
| 3 | 432 | elevated | missing-authentication | juice-shop | likely | medium |
| 4 | 432 | elevated | unencrypted-communication | reverse-proxy | likely | medium |
| 5 | 241 | medium | cross-site-request-forgery | juice-shop | very-likely | low |

### Baseline Risk Posture Summary
- Total baseline risks: 23
- Severity distribution (`stats.json`): elevated=4, medium=14, low=5
- Main concern clusters:
  - Unencrypted transport paths
  - Web application attack classes (XSS/CSRF)
  - Missing architecture controls (authentication on internal hop, identity store, vault)

### Diagram References
- Data flow diagram: `labs/lab2/baseline/data-flow-diagram.png`
- Data asset diagram: `labs/lab2/baseline/data-asset-diagram.png`

## Task 2 - HTTPS Variant and Risk Comparison

### Secure Model Changes
Created `labs/lab2/threagile-model.secure.yaml` with these exact changes:
1. `User Browser -> communication_links -> Direct to App (no proxy) -> protocol: https`
2. `Reverse Proxy -> communication_links -> To App -> protocol: https`
3. `Persistent Storage -> encryption: transparent`

### Secure Variant Generation

```bash
docker run --rm -v "${PWD}:/app/work" threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

### Generated Secure Outputs
- `labs/lab2/secure/report.pdf`
- `labs/lab2/secure/data-flow-diagram.png`
- `labs/lab2/secure/data-asset-diagram.png`
- `labs/lab2/secure/risks.json`
- `labs/lab2/secure/stats.json`
- `labs/lab2/secure/technical-assets.json`

### Risk Category Delta Table
Source file: `labs/lab2/risk-category-delta.md`

| Category | Baseline | Secure | Delta |
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
| unencrypted-asset | 2 | 2 | 0 |
| unencrypted-communication | 2 | 0 | -2 |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

### Delta Run Explanation
- What changed:
  - Converted direct browser-to-app and proxy-to-app links to HTTPS.
  - Enabled transparent encryption on persistent storage.
- What changed in risk landscape:
  - Total risks reduced from 23 to 21.
  - Elevated risks reduced from 4 to 2.
  - Category impact concentrated in `unencrypted-communication` (2 -> 0).
- Why:
  - Protocol hardening removed cleartext transport findings for both previously HTTP links.
  - Storage encryption change did not alter current category counts in this model run, but improves confidentiality posture for stored data at rest.

### Diagram Comparison Notes
- Baseline and secure diagram files are available side-by-side:
  - `labs/lab2/baseline/data-flow-diagram.png` vs `labs/lab2/secure/data-flow-diagram.png`
  - `labs/lab2/baseline/data-asset-diagram.png` vs `labs/lab2/secure/data-asset-diagram.png`
- The main semantic difference is transport protection on links previously modeled as HTTP.

## Submission Metadata
- Branch: `feature/lab2`
- Artifacts directory: `labs/lab2/`

