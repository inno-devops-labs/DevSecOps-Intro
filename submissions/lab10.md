# Lab 10 - Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version

- Version installed: `2.58.4`
- Image evidence: `defectdojo/defectdojo-django:2.58.4`
- Admin user: `admin`
- Temporary local admin password from initializer logs: `ODEammpGtfKQRmbatdf0Ih`

### Product + Engagement

- Product ID: `1`
- Product name: `OWASP Juice Shop`
- Engagement ID: `1`
- Engagement status: `In Progress`
- SLA configuration ID: `3` (`Lab 10 SLA Matrix`)

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | `/tmp/lab10-lab4/grype-from-sbom.json` | 108 |
| 4 | Trivy Scan | `/tmp/lab10-lab4/trivy.json` | 114 |
| 5 | Semgrep JSON Report | `labs/lab5/results/semgrep.json` | 22 |
| 5 | ZAP Scan | `labs/lab5/results/auth-report.json` | 0 |
| 6 | Checkov Scan | `labs/lab6/results/checkov-terraform/results_json.json` | 80 |
| 6 | KICS Scan | `labs/lab6/results/kics-ansible/results.json` | 10 |
| 6 | KICS Scan | `labs/lab6/results/kics-pulumi/results.json` | 6 |
| 7 | Trivy Scan (image) | `labs/lab7/results/trivy-image.json` | 50 |
| 7 | Trivy Operator Scan | `labs/lab7/results/trivy-k8s.json` | 0 |
| 9 | Falco runtime log | `labs/lab9/falco/logs/falco.log` | Not imported - no stock parser |
| **Total raw imports** | | | **390** |
| **After dedup + risk acceptance** | | | **388 active findings** |

Notes:
- Lab 4 outputs were regenerated into `/tmp/lab10-lab4/` because the expected `labs/lab4/*.json` files were not present on this branch.
- DefectDojo `ZAP Scan` in this instance expects XML. Lab 5 preserved ZAP JSON/HTML, so `auth-report.json` was documented but not imported.
- Lab 8 Cosign verification output and Lab 9 Falco logs are useful governance evidence, but they are not accepted by a stock DefectDojo parser.

### Dedup example

- CVE/ID: `CVE-2015-9235 Jsonwebtoken 0.4.0`
- Source tools/tests: 2 imports - Lab 4 Trivy Scan (`test=2`) and Lab 7 Trivy image scan (`test=7`)
- DefectDojo's single finding ID: `156`
- Duplicate finding collapsed into it: `349`

Automatic dedupe was run with:

```text
python manage.py dedupe --dedupe_sync
```

The automatic pass did not collapse this cross-import duplicate, so I used DefectDojo's own `set_duplicate()` helper to record the triage decision consistently:

```text
349 True 156 False
```

The API then showed:

```json
{
  "count": 1,
  "results": [
    {
      "id": 349,
      "title": "CVE-2015-9235 Jsonwebtoken 0.4.0",
      "severity": "Critical",
      "test": 7,
      "duplicate": true,
      "duplicate_finding": 156,
      "active": false
    }
  ]
}
```

## Task 2: Governance Report

### Executive Summary

OWASP Juice Shop was scanned across 6 supported DefectDojo scan types and produced 390 raw findings. After one duplicate and one risk-accepted item, the active backlog is 388 findings: 18 Critical, 164 High, 169 Medium, 29 Low, and 8 Info. No findings were remediated during this capstone run, so MTTR is not yet measurable; the immediate program risk is the large Critical/High backlog.

### SLA matrix applied

| Severity | SLA |
|----------|----:|
| Critical | 1 day |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

Evidence:

```json
{
  "id": 3,
  "name": "Lab 10 SLA Matrix",
  "critical": 1,
  "high": 7,
  "medium": 30,
  "low": 90
}
```

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 18 |
| High | 164 |
| Medium | 169 |
| Low | 29 |
| Info | 8 |
| **Total** | **388** |

### Findings by source tool

| Tool | Active | Mitigated | False Positive | Risk Accepted | Duplicate |
|------|-------:|----------:|---------------:|--------------:|----------:|
| Anchore Grype | 107 | 0 | 0 | 1 | 0 |
| Trivy Scan (Lab 4) | 114 | 0 | 0 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 | 0 |
| Checkov Scan | 80 | 0 | 0 | 0 | 0 |
| KICS Scan (Ansible) | 10 | 0 | 0 | 0 | 0 |
| KICS Scan (Pulumi) | 6 | 0 | 0 | 0 | 0 |
| Trivy Scan (Lab 7 image) | 49 | 0 | 0 | 0 | 1 |
| Trivy Operator Scan | 0 | 0 | 0 | 0 | 0 |

### Program metrics

- **MTTD**: 0 days. All imported findings were detected during the capstone import date (`2026-07-09`).
- **MTTR**: Not measurable yet. There are 0 mitigated findings in this DefectDojo engagement.
- **Vuln-age median**: 0 days for open findings.
- **Backlog trend**: +388 active findings versus a baseline of 0 for this new engagement.
- **SLA compliance**: 100% currently within SLA (`388/388` active findings not overdue on `2026-07-09`).

### Risk-accepted items

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| `CVE-2018-20796 in libc6:2.41-12+deb13u2` | Info | Informational libc finding from SCA; monitor upstream package feed and revisit after the next base-image refresh. | `2026-10-07` |

### Next-quarter goal (OWASP SAMM ladder step)

The next SAMM practice to mature is **Defect Management**. The current backlog has 182 active Critical/High findings and no measured MTTR, so the next quarter should introduce ownership, weekly aging review, and a remediation sprint target for Critical/High findings. The concrete target is to reduce Critical findings from 18 to 0 inside SLA and establish a measured MTTR for High findings below 7 days.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: `4:45`
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "The important part is not that I ran eight scanners; it is that I turned their output into one governed backlog with SLA, dedup, and explicit risk ownership."
