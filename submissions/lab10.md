# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version

- Version installed: **2.58.4**
- API base: `http://localhost:8080/api/v2`

The generated administrator password and API token were stored only under
`labs/lab10/work/` with restrictive permissions and were not committed.

### Product + Engagement

- Product ID: **1**
- Product name: **OWASP Juice Shop**
- Engagement ID: **1**
- Engagement status: **In Progress**
- SLA configuration ID: **3**

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | `labs/lab4/grype-from-sbom.json` | 104 |
| 4 | Trivy Scan | `labs/lab4/trivy.json` | 109 |
| 5 | Semgrep Pro JSON Report | `labs/lab5/results/semgrep.json` | 0 |
| 6 | Checkov Scan | `labs/lab6/results/checkov-terraform/results_json.json` | 78 |
| 6 | KICS Scan | `labs/lab6/results/kics-ansible/results.json` | 10 |
| 6 | KICS Scan | `labs/lab6/results/kics-pulumi/results.json` | 6 |
| 7 | Trivy Scan | `labs/lab7/results/trivy-image.json` | 50 |
| 7 | Trivy Operator Scan | `labs/lab7/results/trivy-k8s.json` | 0 |
| **Total raw imports** | | | **357** |
| **After dedup** | | | **356** |

Cosign verification from Lab 8 and Falco JSON lines from Lab 9 were retained as program
evidence, but they were not misrepresented as supported DefectDojo parser imports.

### Dedup example

- CVE/ID: **CVE-2010-4756**
- Finding title: **CVE-2010-4756 in libc6:2.41-12+deb13u2**
- Number of source tools: **2**
- Source tools: **Anchore Grype, Trivy Scan**
- Records collapsed: **2**
- DefectDojo single finding ID: **86**
- Deduplication action: **Automatic import deduplication**

## Task 2: Governance Report

### Executive Summary

Juice Shop was aggregated from **8 successful scan imports** and currently has
**354 actionable open findings**, including **16 Critical** and **150 High**.
Mean Time to Remediate for closed findings is **0.71 days**, while current SLA compliance
is **100.0%**. The exercise closed `GHSA-c7hr-j4mj-j2w6 in jsonwebtoken:0.1.0` and created one temporary,
expiring risk acceptance rather than silently suppressing the remaining item.

### Findings by severity — active actionable only

| Severity | Count |
|----------|------:|
| Critical | 16 |
| High | 150 |
| Medium | 154 |
| Low | 26 |
| Info | 8 |

### Findings by source tool

| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 102 | 1 | 0 | 1 |
| Checkov Scan | 78 | 0 | 0 | 0 |
| KICS Scan | 16 | 0 | 0 | 0 |
| Trivy Scan | 158 | 0 | 0 | 0 |

### Program metrics

- **MTTD:** 0.7 days, measured as DefectDojo creation time minus finding detection date.
- **MTTR:** 0.71 days for mitigated findings.
- **Vulnerability-age median:** 0.71 days for actionable open findings.
- **Backlog trend:** -2 actionable findings during the triage exercise
  (356 → 354).
- **SLA compliance:** 100.0% (347 of 347).
- **Applied SLA matrix:** Critical 1 day, High 7 days, Medium 30 days, Low 90 days.

### Risk-accepted items — all have expiry

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| #54 — CVE-2018-20796 in libc6:2.41-12+deb13u2 | Info | Accepted for the course governance exercise; expires automatically after 90 days. | 2026-10-08T17:01:51.583360Z |

### Next-quarter goal — OWASP SAMM Defect Management

The next maturity step is to operationalize **Defect Management** with an owner, weekly
SLA-breach review, and automated escalation for Critical and High findings. The current
program has a median open-finding age of **0.71 days** and SLA compliance of
**100.0%**, so the next-quarter target is to raise compliance above 90% and keep
High-severity MTTR below seven days while adding a supported ingestion path for Falco
runtime alerts.

## Bonus: Interview Walkthrough

- Walkthrough script: `submissions/lab10-walkthrough.md`
- Estimated runtime at 130 words/minute: recorded in the walkthrough file
- Practiced runtime: **04:40**
- Two anticipated Q&A questions covered: **yes**
- Strongest claim: **The program binds prevention, runtime detection, cryptographic
  provenance, and SLA-governed remediation to one product record instead of treating
  scanner output as unrelated files.**

After reading the script aloud, run:

```bash
./scripts/lab10_mark_practice.sh MM:SS
```

The helper rejects times above five minutes and replaces the pending marker before the
files are committed.
