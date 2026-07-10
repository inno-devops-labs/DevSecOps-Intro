# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version

- Version installed: `defectdojo/defectdojo-django:latest`
- Deployment mode used: `release`
- UI URL: `http://localhost:8080`
- Note: `dev` mode was attempted first, but the local build required BuildKit and the release mode was used for the lab run.

### Product + Engagement

- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement name: Course Semester Run
- Engagement status: In Progress

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | `labs/lab4/grype-from-sbom.json` | 104 |
| 4 | Trivy Scan | `labs/lab4/trivy.json` | 113 |
| 5 | Semgrep JSON Report | `labs/lab5/results/semgrep.json` | 22 |
| 5 | ZAP Scan | `labs/lab5/results/auth-report.json` | 0 |
| 6 | Checkov Scan | `labs/lab6/results/checkov-terraform/results_json.json` | 80 |
| 6 | KICS Scan | `labs/lab6/results/kics-ansible/results.json` | 10 |
| 6 | KICS Scan | `labs/lab6/results/kics-pulumi/results.json` | 6 |
| 7 | Trivy Scan (image) | `labs/lab7/results/trivy-image.json` | 50 |
| 7 | Trivy Operator Scan | `labs/lab7/results/trivy-k8s.json` | 0 |
| 8 | Cosign verification | `labs/lab8/verify-original.json` | Not imported |
| 9 | Falco runtime alerts | `labs/lab9/falco/logs/falco.log` | Not imported |
| **Total raw imports** | | | **385** |
| **After dedup** | | | **385 unique findings** |

### Import notes

The ZAP import was attempted through the `ZAP Scan` parser, but DefectDojo rejected `auth-report.json` because this parser expects XML. The failed import response was preserved in `labs/lab10/imports/import-results-auth-report.json`.

Lab 8 Cosign verification output was not imported because the lab setup did not provide a native DefectDojo parser for this verification log. Lab 9 Falco runtime alerts were also not imported because the assignment identifies them as a custom-format source to document if unsupported.

### Dedup example

A cross-tool duplicate finding was not observed in this imported dataset.

- Total findings after import: 385
- Non-duplicate findings: 385
- Duplicate findings: 0

DefectDojo deduplication was enabled, but the available Lab 4-7 scanner outputs were kept as unique findings. Instead of claiming a false dedup result, this report documents the actual observed state: no duplicate findings were produced by this dataset.

One useful correlation example still visible across tools is:

- Finding: `Secret Detected in /juice-shop/lib/insecurity.ts - Asymmetric Private Key`
- Sources:
  - Lab 4 Trivy Scan
  - Lab 7 Trivy image scan
- Severity: High
- Interpretation: the same secret exposure class appears both in dependency/image scanning evidence and in the later container image scan context, increasing confidence that it should be handled as a real issue.

---

## Task 2: Governance Report

### SLA matrix

The following SLA matrix was applied/documented for the DefectDojo engagement:

| Severity | Fix SLA | Owner | Escalation |
|----------|--------:|-------|------------|
| Critical | 24 hours | Security/on-call owner | Immediate escalation |
| High | 7 days | Service team | Ticket + security follow-up |
| Medium | 30 days | Service team | Backlog grooming |
| Low | 90 days / accept | Tech lead | Quarterly review |

### Executive Summary

OWASP Juice Shop was scanned through a multi-tool DevSecOps pipeline and centralized in DefectDojo as a single vulnerability-management program. The current baseline contains 385 active findings: 17 Critical, 164 High, 168 Medium, 27 Low, and 9 Informational. No findings have been mitigated, risk-accepted, or marked false positive yet, so this report represents the initial triage baseline before remediation work begins.

### Findings by severity

| Severity | Count |
|----------|------:|
| Critical | 17 |
| High | 164 |
| Medium | 168 |
| Low | 27 |
| Info | 9 |
| **Total active** | **385** |

### Findings by source tool

| Tool / Import | Active | Mitigated | False Positive | Risk Accepted |
|---------------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 104 | 0 | 0 | 0 |
| Trivy Scan — Lab 4 | 113 | 0 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 |
| ZAP Scan | 0 | 0 | 0 | 0 |
| Checkov Scan | 80 | 0 | 0 | 0 |
| KICS Scan — Ansible | 10 | 0 | 0 | 0 |
| KICS Scan — Pulumi | 6 | 0 | 0 | 0 |
| Trivy Scan — image | 50 | 0 | 0 | 0 |
| Trivy Operator Scan | 0 | 0 | 0 | 0 |
| **Total** | **385** | **0** | **0** | **0** |

### Program metrics

- **MTTD**: not fully measurable from the imported historical scanner files because the original vulnerability-introduction timestamps are not available. For this lab baseline, detection-to-centralization happened during the same DefectDojo import session.
- **MTTR**: not applicable yet because there are 0 mitigated findings.
- **Vuln-age median**: 0 days at baseline import time; all findings were first centralized during this Lab 10 run.
- **Backlog trend**: +385 findings versus the initial empty DefectDojo baseline.
- **SLA compliance**: not yet measurable for closed findings because 0 findings have been closed. The SLA exposure is now explicit: 17 Critical findings require 24-hour treatment, 164 High findings require 7-day treatment, 168 Medium findings require 30-day treatment, and 27 Low findings require 90-day treatment or formal acceptance.

### Current finding state

| State | Count |
|-------|------:|
| Active | 385 |
| Verified | 157 |
| False Positive | 0 |
| Risk Accepted | 0 |
| Mitigated | 0 |
| Duplicate | 0 |

### Risk-accepted items

No findings were risk-accepted during this baseline run.

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| None | N/A | No risk acceptance was applied in this lab run | N/A |

Policy note: any future Risk Accepted finding must include an explicit expiry date and a re-review owner. Open-ended acceptance is not allowed.

### Highest-priority remediation queue

| Priority | Finding / Category | Source | Reason |
|----------|-------------------|--------|--------|
| 1 | Critical dependency findings | Grype / Trivy | Critical severity items should be handled first under the 24-hour SLA. |
| 2 | High dependency findings | Grype / Trivy | Large High backlog increases patch debt and should be batched by package/component. |
| 3 | Secret findings | Trivy / KICS | Secrets are high-confidence and can often be remediated directly by removing hardcoded material and rotating exposed values. |
| 4 | Semgrep injection findings | Semgrep | Code-level injection findings require developer review and targeted fixes. |
| 5 | IaC public exposure findings | Checkov / KICS | Infrastructure findings should be fixed before deployment because they are cheaper to prevent than to remediate after release. |

### Next-quarter goal

The next OWASP SAMM-aligned improvement should be **Defect Management**. The current baseline has 385 active findings and no closed findings yet, so the immediate maturity step is to move from centralized discovery to enforceable ownership, SLA tracking, and remediation verification. The next quarter goal is to assign owners for all Critical and High findings, close or formally risk-accept every Critical item, and reduce the High backlog by at least 30%.

### Evidence commands

```bash
curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/findings/?limit=1" | jq .count

curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/products/" | jq '.results[] | {id, name}'

curl -s -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/tests/?engagement=$ENGAGEMENT_ID&limit=200" \
  | jq '.results[] | {id, scan_type}'

jq '
  [.results[] | select(.active == true) | .severity]
  | group_by(.)
  | map({severity: .[0], count: length})
' labs/lab10/work/findings.json
```

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4 minutes 45 seconds
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "The important part was not running nine scanners; it was turning their output into an owned backlog with SLA, state, and measurable risk."
