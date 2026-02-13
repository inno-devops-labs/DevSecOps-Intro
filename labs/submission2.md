# Lab 2 Submission

## Task 1 — Threagile Baseline Model

### Baseline Generation
Command used:

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

Outputs generated:
- `lab2/baseline/report.pdf`
- `lab2/baseline/data-flow-diagram.png`
- `lab2/baseline/data-asset-diagram.png`
- `lab2/baseline/risks.json`, `lab2/baseline/stats.json`, `lab2/baseline/technical-assets.json`

### Baseline Diagrams
- Data Flow Diagram: `lab2/baseline/data-flow-diagram.png`
- Data Asset Diagram: `lab2/baseline/data-asset-diagram.png`

![Baseline DFD](lab2/baseline/data-flow-diagram.png)
![Baseline Data Assets](lab2/baseline/data-asset-diagram.png)

### Risk Ranking Method
Weights and formula used:
- Severity: critical=5, elevated=4, high=3, medium=2, low=1
- Likelihood: very-likely=4, likely=3, possible=2, unlikely=1
- Impact: high=3, medium=2, low=1
- Composite score = Severity*100 + Likelihood*10 + Impact

### Top 5 Risks (Baseline)
| Category | Asset | Severity | Likelihood | Impact | Composite |
|---|---|---|---|---|---:|
| unencrypted-communication | user-browser | elevated | likely | high | 433 |
| cross-site-scripting | juice-shop | elevated | likely | medium | 432 |
| missing-authentication | juice-shop | elevated | likely | medium | 432 |
| unencrypted-communication | reverse-proxy | elevated | likely | medium | 432 |
| cross-site-request-forgery | juice-shop | medium | very-likely | low | 241 |

### Critical Security Concerns (Baseline)
- Unencrypted communication appears twice (browser direct to app and proxy to app), indicating clear exposure to interception and session/token leakage on HTTP links.
- Elevated XSS risk on the application suggests a high-likelihood client-side compromise path for users and admin sessions.
- Missing authentication findings on a core internal link indicate weak access control assumptions between proxy and app.
- CSRF remains very likely due to a lack of robust anti-CSRF controls in the baseline model.

## Task 2 — HTTPS Variant & Risk Comparison

### Secure Model Changes
Changes applied in `lab2/threagile-model.secure.yaml`:
- User Browser → Direct to App: `protocol: https`
- Reverse Proxy → To App: `protocol: https`
- Persistent Storage: `encryption: transparent`

### Secure Generation
Command used:

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

Outputs generated:
- `lab2/secure/report.pdf`
- `lab2/secure/data-flow-diagram.png`
- `lab2/secure/data-asset-diagram.png`
- `lab2/secure/risks.json`, `lab2/secure/stats.json`, `lab2/secure/technical-assets.json`

### Risk Category Delta Table (Baseline vs Secure)
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
| unencrypted-asset | 2 | 1 | -1 |
| unencrypted-communication | 2 | 0 | -2 |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

### Delta Run Explanation
- Model changes: HTTPS was enforced on browser-to-app and proxy-to-app links, and storage encryption was enabled for persistent storage.
- Observed results: unencrypted-communication risks dropped from 2 to 0; unencrypted-asset decreased by 1. Total risks reduced from 23 (baseline) to 20 (secure).
- Analysis: TLS removes cleartext communication exposure, eliminating transport-related risks. Storage encryption mitigates a portion of data-at-rest exposure, reducing unencrypted-asset risk count.

### Diagram Comparison
- Secure DFD: `lab2/secure/data-flow-diagram.png`
- Secure Data Assets: `lab2/secure/data-asset-diagram.png`

![Secure DFD](lab2/secure/data-flow-diagram.png)
![Secure Data Assets](lab2/secure/data-asset-diagram.png)
