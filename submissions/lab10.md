# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version

- Version installed: DefectDojo `3.0.200` (`git describe --tags --always`: `3.0.200`, commit `a7eb77f`)
- Image evidence: `defectdojo/defectdojo-django:latest`, local build required for dev compose entrypoints on Apple Silicon.

### Product + Engagement

- Product ID: `3`
- Product name: OWASP Juice Shop
- Engagement ID: `3`
- Engagement status: In Progress
- SLA configuration applied through `/api/v2/sla_configurations/1/`:
  - Critical: 1 day / 24 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | `grype-from-sbom.json` | 107 |
| 4 | Trivy Scan | `trivy.json` | 113 |
| 5 | Semgrep JSON Report | `semgrep.json` | 0 - source file unavailable locally |
| 5 | ZAP Scan | `auth-report.json` | 0 - source file unavailable locally |
| 6 | Checkov Scan | `results_json.json` | 80 |
| 6 | KICS Scan | `kics-ansible/results.json` | 10 |
| 6 | KICS Scan | `kics-pulumi/results.json` | 6 |
| 7 | Trivy Scan (image) | `trivy-image.json` | 50 |
| 7 | Trivy Operator Scan | `trivy-k8s.json` | 0 |
| 9 | Generic Findings Import | `falco-generic.json` | 4 |
| **Total raw imports** | | | **370** |
| **After dedup** | | | **368 active unique findings** |

### Dedup example

- CVE/ID: `CVE-2026-45447` in `libssl3t64 3.5.5-1~deb13u2`
- Number of source tools: 3 — Anchore Grype, Trivy lab4, Trivy lab7 image
- DefectDojo canonical finding ID: `301`
- Duplicate findings marked: `414`, `609`

DefectDojo did not auto-link this CVE because the parsers emitted slightly different titles and no normalized `cve` field, so I treated this as a manual dedup action during triage.

## Task 2: Governance Report

### Executive Summary

Juice Shop, scanned across 6 DefectDojo source types, currently has 368 active unique findings after dedup: 18 Critical and 151 High. Mean Time to Remediate is not yet available because no findings were closed in this fresh import period. 100% of open findings are currently within the configured SLA windows because the imports were created on July 3, 2026.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 18 |
| High | 151 |
| Medium | 161 |
| Low | 29 |
| Info | 9 |

### Findings by source tool

| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 107 | 0 | 0 | 0 |
| Trivy Scan (Lab 4) | 112 | 0 | 0 | 0 |
| Checkov Scan | 80 | 0 | 0 | 0 |
| KICS Scan (Ansible) | 10 | 0 | 0 | 0 |
| KICS Scan (Pulumi) | 6 | 0 | 0 | 0 |
| Trivy Scan (Lab 7 image) | 49 | 0 | 0 | 0 |
| Trivy Operator Scan | 0 | 0 | 0 | 0 |
| Generic Findings Import (Falco) | 4 | 0 | 0 | 0 |

### Program metrics

- **MTTD** (Mean Time to Detect): 0 days; all imported findings were detected and ingested on July 3, 2026.
- **MTTR** (Mean Time to Remediate): N/A; no findings have been mitigated yet in DefectDojo.
- **Vuln-age median** (open findings): 0 days.
- **Backlog trend**: +368 active unique findings versus the pre-capstone baseline of 0 tracked findings.
- **SLA compliance**: 100% currently within SLA; closed-within-SLA is N/A until remediation starts.

### Risk-accepted items

No items are risk-accepted. If a finding is risk-accepted later, it must include an owner, reason, and expiry date; otherwise it becomes silent backlog rather than governed risk.

### Next-quarter goal (OWASP SAMM ladder step)

The next maturity step should be SAMM Defect Management: move from aggregation to governed remediation. The data says the backlog is dominated by 169 Critical/High active findings, so the concrete goal is to close or formally risk-accept 80% of Critical findings within the 24-hour SLA and 50% of High findings within 7 days, using DefectDojo as the single queue and Falco runtime alerts as escalation signals.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4 minutes 45 seconds
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "I did not stop at scanner output; I turned it into a governed backlog with owners, SLA pressure, and runtime evidence."
