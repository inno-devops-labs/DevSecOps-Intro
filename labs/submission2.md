# Lab 2 — Threagile Threat Modeling

## Task 1 — Baseline Threat Model

### Commands Run
```bash
mkdir -p labs/lab2/baseline labs/lab2/secure

docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

### Generated Outputs (Baseline)
- `labs/lab2/baseline/report.pdf`
- `labs/lab2/baseline/data-flow-diagram.png`
- `labs/lab2/baseline/data-asset-diagram.png`
- `labs/lab2/baseline/risks.json`
- `labs/lab2/baseline/stats.json`
- `labs/lab2/baseline/technical-assets.json`

### Risk Ranking Methodology
Weights used:
- Severity: critical=5, elevated=4, high=3, medium=2, low=1
- Likelihood: very-likely=4, likely=3, possible=2, unlikely=1
- Impact: high=3, medium=2, low=1

Composite score:
```
Severity*100 + Likelihood*10 + Impact
```

### Top 5 Risks (Baseline)
| Rank | Risk | Severity | Likelihood | Impact | Category | Asset | Composite |
|---:|---|---|---|---|---|---|---:|
| 1 | Unencrypted Communication (Direct to App, browser → app, auth data) | elevated | likely | high | unencrypted-communication | user-browser | 433 |
| 2 | Unencrypted Communication (Reverse Proxy → App) | elevated | likely | medium | unencrypted-communication | reverse-proxy | 432 |
| 3 | Cross‑Site Scripting (XSS) at Juice Shop | elevated | likely | medium | cross-site-scripting | juice-shop | 432 |
| 4 | Missing Authentication on Proxy → App link | elevated | likely | medium | missing-authentication | juice-shop | 432 |
| 5 | CSRF risk via Direct to App | medium | very-likely | low | cross-site-request-forgery | juice-shop | 241 |

### Baseline Observations
- The highest‑scoring risks are driven by **unencrypted HTTP links** carrying auth/session data.
- App‑layer threats (XSS/CSRF) remain significant due to the deliberately vulnerable training app.
- The proxy → app link is flagged for missing authentication, reinforcing the need for hardening internal hops.

### Baseline Diagrams
- Data Flow Diagram: `labs/lab2/baseline/data-flow-diagram.png`
- Data Asset Diagram: `labs/lab2/baseline/data-asset-diagram.png`

---

## Task 2 — Secure Variant & Comparison

### Secure Model Changes
Saved as: `labs/lab2/threagile-model.secure.yaml`
- User Browser → Direct to App: `protocol: https`
- Reverse Proxy → communication_links: `protocol: https`
- Persistent Storage: `encryption: transparent`

### Secure Variant Generation
```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

### Generated Outputs (Secure)
- `labs/lab2/secure/report.pdf`
- `labs/lab2/secure/data-flow-diagram.png`
- `labs/lab2/secure/data-asset-diagram.png`
- `labs/lab2/secure/risks.json`
- `labs/lab2/secure/stats.json`
- `labs/lab2/secure/technical-assets.json`

### Risk Category Delta Table (Baseline vs Secure)
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

### Delta Analysis
- Switching **HTTP → HTTPS** on the browser → app and proxy → app links removed **unencrypted-communication** risks (Δ = -2).
- Enabling **transparent storage encryption** reduced **unencrypted-asset** risks (Δ = -1).
- Other risk categories remained unchanged because the application logic and trust boundaries did not change.

### Diagram Comparison
- Baseline DFD: `labs/lab2/baseline/data-flow-diagram.png`
- Secure DFD: `labs/lab2/secure/data-flow-diagram.png`
- Baseline Data Asset Diagram: `labs/lab2/baseline/data-asset-diagram.png`
- Secure Data Asset Diagram: `labs/lab2/secure/data-asset-diagram.png`

---

## Challenges & Notes
- Threagile printed font cache warnings during PDF generation, but outputs were created successfully.
