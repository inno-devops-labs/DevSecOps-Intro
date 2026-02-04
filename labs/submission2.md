## Overview
Threagile was run locally using the `labs/lab2/baseline/threagile-model.yaml`.  
Local setup: Kali Linux, Threagile CLI, output generated in `labs/lab2/baseline`.

## Artifacts
The following files were produced:

- `labs/lab2/baseline/threagile-model.yaml`
- `labs/lab2/baseline/report.pdf`
- `labs/lab2/baseline/data-flow-diagram.png`
- `labs/lab2/baseline/data-asset-diagram.png`
- `labs/lab2/baseline/risks.json`
- `labs/lab2/baseline/stats.json`
- `labs/lab2/baseline/technical-assets.json`
- `labs/lab2/baseline/trisks.xlsx`

## Top 5 Risks

| Severity  | Category                         | Asset           | Likelihood   | Impact | Composite Score |
|-----------|---------------------------------|----------------|-------------|--------|----------------|
| Elevated  | Unencrypted Communication        | Direct To App  | Likely      | High   | 461            |
| Elevated  | Unencrypted Communication        | To Reverse Proxy| Likely     | High   | 461            |
| Elevated  | Cross-Site Scripting (XSS)      | Juice Shop     | Likely      | Medium | 434            |
| Elevated  | Missing Authentication           | Juice Shop     | Likely      | Medium | 434            |
| Medium    | Container Base Image Backdooring | Juice Shop     | Unlikely    | Medium | 222            |

> Composite score = Severity100 + Likelihood10 + Impact  
> Weights used:
> Severity: critical(5)>elevated(4)>high(3)>medium(2)>low(1),
> Likelihood: very-likely(4)>likely(3)>possible(2)>unlikely(1), I
> mpact: high(3)>medium(2)>low(1)

## Threat Dragon Comparison
- **Overlaps:**  
  1. Unencrypted Communication → Direct To App  
  2. Missing Authentication → Juice Shop  

- **Difference:**  
  - Cross-Site Request Forgery (CSRF) via Reverse Proxy → App appears in Threagile but not in Threat Dragon.

## Delta Run
- **Change:** Updated communication link `Reverse Proxy → App` to HTTPS in `threagile-model.yaml`.  
- **Before:** 3 unencrypted-communication risks (Direct To App, To Reverse Proxy, Reverse Proxy → App)  
- **After:** 2 unencrypted-communication risks (Direct To App, To Reverse Proxy)  
- **Reason:** Switching to HTTPS removed the risk associated with `Reverse Proxy → App`.

## Stats Snapshot
```json
[{"category":"unencrypted-asset","risk_status":"unchecked","severity":"medium","exploitation_likelihood":"unlikely","exploitation_impact":"medium","title":"\u003cb\u003eUnencrypted Technical Asset\u003c/b\u003e named \u003cb\u003eJuice Shop\u003c/b\u003e","synthetic_id":"unencrypted-asset@juice-shop","most_relevant_data_asset":"","most_relevant_technical_asset":"juice-shop","most_relevant_trust_boundary":"","most_relevant_shared_runtime":"","most_relevant_communication_link":"","data_breach_probability":"improbable","data_breach_technical_assets":["juice-shop"]}, ...]
```
## GitHub Social Interaction (Bonus)
Rationale: Stars and followers help identify popular projects, build community trust, and support collaboration in open-source and team-based projects. They make it easier to discover valuable work and engage with contributors.
