# Metrics Snapshot — Lab 10

- Date captured: 2026-03-20
- Active findings:
  - Critical: 21
  - High: 116
  - Medium: 87
  - Low: 28
  - Informational: 39
  - **Total: 291**

## Findings per Tool
| Tool     | Critical | High | Medium | Low | Info | Total |
|----------|----------|------|--------|-----|------|-------|
| ZAP      | 0        | 0    | 2      | 6   | 4    | 12    |
| Semgrep  | 0        | 7    | 18     | 0   | 0    | 25    |
| Nuclei   | 0        | 0    | 1      | 1   | 23   | 25    |
| Grype    | 11       | 52   | 31     | 3   | 12   | 109   |
| Trivy    | 10       | 57   | 35     | 18  | 0    | 120   |
| **Total**| **21**   |**116**|**87** |**28**|**39**|**291**|

## Verified vs Mitigated
- Verified: 116 (Trivy findings auto-verified by scanner)
- Mitigated: 0 (no findings closed yet — baseline capture)
- All findings status: Active, unmitigated

## SLA Outlook
- Critical findings (21): require remediation within 7 days
- High findings (116): require remediation within 30 days
- No findings currently breaching SLA (engagement opened today)
- Items due within 14 days: all 21 Critical findings

## Top Risk Areas
- Dependency vulnerabilities dominate (Grype + Trivy = 229 findings, 79% of total)
- 21 Critical CVEs across vm2, Node.js runtime, jsonwebtoken, crypto-js, lodash
- Source code vulnerabilities (Semgrep): 25 findings including SQL injection and hardcoded JWT secret
- Deployment/runtime misconfigurations (ZAP + Nuclei): 37 findings including missing CSP, open CORS
