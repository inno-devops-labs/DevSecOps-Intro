# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: `defectdojo/defectdojo-django:2.58.2` and `defectdojo/defectdojo-nginx:2.58.2`
- Deployment: official Docker Compose stack
- Local URL used during the run: `http://127.0.0.1:8081`
- Initializer status: completed successfully

### Product + Engagement
- Product ID: `1`
- Product name: OWASP Juice Shop
- Engagement ID: `1`
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | `lab4-grype.json` | 107 |
| 4 | Trivy Scan | `trivy.json` | Not imported — report not found |
| 5 | Semgrep JSON Report | `semgrep.json` | 22 |
| 5 | ZAP Scan | `auth-report.json` | Not imported — report not found |
| 6 | Checkov Scan | `results_json.json` | 80 |
| 6 | KICS Scan | `kics-ansible/results.json` | 10 |
| 6 | KICS Scan | `kics-pulumi/results.json` | 6 |
| 7 | Trivy Scan (image) | `trivy-image.json` | 50 |
| 7 | Trivy Operator Scan | `trivy-k8s.json` | 0 |
| **Total raw imports** | | | **275** |
| **After dedup** | | | **275 unique findings** |

Seven reports were accepted by DefectDojo, covering six distinct scan types. The Trivy Operator report created a test successfully but produced zero findings. Lab 8 Cosign verification output is supporting evidence rather than a vulnerability scan, and the Lab 9 Falco log was not imported because DefectDojo 2.58.2 has no native Falco parser.

### Dedup example (Lecture 10 slide 11)
- CVE/ID: `CVE-2026-45447`
- Number of source tools: `2 — Anchore Grype and Trivy Scan`
- DefectDojo's single finding ID: `not created automatically`
- Related finding IDs: Grype finding `9`, Trivy finding `226`
- Component: `libssl3t64`
- Component version: `3.5.5-1~deb13u2`

The same CVE, component and version appeared in both tools, but DefectDojo retained two findings because the parsers generated different titles and hash codes. A total of 36 shared vulnerability identifiers were found between the Grype and Trivy tests, but none was marked as a duplicate. Therefore, cross-tool correlation was verified, while automatic cross-tool deduplication was not achieved in this run.

## Task 2: Governance Report

### Executive Summary (3 sentences)
Juice Shop, scanned through seven imported reports across six scan types, currently has 275 open findings, including 12 Critical and 119 High findings. Mean Time to Remediate cannot yet be calculated because no findings were mitigated during the reporting period. Closed-finding SLA compliance is also unavailable because the engagement contains no closed findings.

The SLA matrix was applied before import: Critical `24 hours`, High `7 days`, Medium `30 days`, and Low `90 days`.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 12 |
| High | 119 |
| Medium | 128 |
| Low | 7 |
| Informational | 9 |
| **Total** | **275** |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 107 | 0 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 |
| Checkov Scan | 80 | 0 | 0 | 0 |
| KICS Scan | 16 | 0 | 0 | 0 |
| Trivy Scan | 50 | 0 | 0 | 0 |
| Trivy Operator Scan | 0 | 0 | 0 | 0 |
| **Total** | **275** | **0** | **0** | **0** |

### Program metrics
- **MTTD** (Mean Time to Detect): approximately `0.80 days`. This was calculated as DefectDojo creation time minus the scanner-provided finding date; the reports supplied date-only values, so sub-day precision is not meaningful.
- **MTTR** (Mean Time to Remediate): `N/A` — no findings have a mitigation timestamp.
- **Vuln-age median** (open findings): approximately `0.80 days`.
- **Backlog trend**: `+0 findings` versus the initial post-import baseline of `275`; a meaningful trend requires at least one later measurement.
- **SLA compliance**: `N/A` — no findings were closed, so there is no closed sample to evaluate against SLA.

### Risk-accepted items (must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| None | — | No findings were risk accepted in this engagement. | — |

No risk acceptance was used to reduce the reported backlog. Any future risk-accepted finding must include a business justification, responsible owner and explicit expiry date.

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
The next OWASP SAMM practice to mature is **Defect Management**. The current baseline is 275 active findings with no closed sample, so the next-quarter targets are High-severity MTTR below seven days and at least 90% of closures completed within SLA. This requires automatic ownership routing, ticket synchronization, mandatory retest evidence before closure, and normalized Grype/Trivy identifiers so the same vulnerability is not counted twice.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: `4 minutes 43 seconds estimated runtime at approximately 135 words per minute; replace with the measured read-aloud time before submission`
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): “A vulnerability-management program must report failed correlation as a control gap instead of silently treating duplicate scanner records as separate risks.”
