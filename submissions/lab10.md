# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Deployment: local Docker Compose deployment from `django-DefectDojo`
- Django image: `defectdojo/defectdojo-django:latest`
- Nginx image: `defectdojo/defectdojo-nginx:latest`

### Product + Engagement
- Product ID: `1`
- Product name: `OWASP Juice Shop`
- Engagement ID: `1`
- Engagement status: `In Progress`

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | `grype-from-sbom.json` | 0 (`file not found`) |
| 4 | Trivy Scan | `trivy.json` | 0 (`file not found`) |
| 5 | Semgrep Pro JSON Report | `semgrep.json` | 0 direct parser count shown in import response; findings present in engagement data |
| 5 | ZAP Scan | `auth-report.json` | 0 (`Wrong file format, please use xml`) |
| 6 | Checkov Scan | `results_json.json` | 80 |
| 6 | KICS Scan | `kics-ansible/results.json` | 10 |
| 6 | KICS Scan | `kics-pulumi/results.json` | 6 |
| 7 | Trivy Scan | `trivy-image.json` | 50 |
| 7 | Trivy Operator Scan | `trivy-k8s.json` | imported, but not reflected as separate finding rows in the final per-test count snapshot |
| **Total raw imports attempted** | | | **7 successful POST imports, 2 skipped, 1 parser mismatch** |
| **After dedup / final engagement count** | | | **146 findings** |

### Import notes
- `labs/lab4/grype-from-sbom.json` and `labs/lab4/trivy.json` were not present in this branch, so the importer skipped both.
- `labs/lab5/results/auth-report.json` was valid ZAP JSON for the lab workflow, but this DefectDojo parser expected XML and returned: `Internal error: Wrong file format, please use xml.`
- The main import set still exceeded the required 6 scan types / imports for the capstone flow.

### Tests created in DefectDojo

| Test ID | Scan type |
|--------:|-----------|
| 1 | Semgrep Pro JSON Report |
| 2 | ZAP Scan |
| 3 | Checkov Scan |
| 4 | KICS Scan |
| 5 | KICS Scan |
| 6 | Trivy Scan |
| 7 | Trivy Operator Scan |

### Dedup example (Lecture 10 slide 11)
In this reduced dataset I could not produce a reliable cross-tool CVE dedup example, because the overlapping Lab 4 SCA imports (`grype-from-sbom.json` and `trivy.json`) were missing and the ZAP JSON import was rejected by the installed parser. The engagement still demonstrates centralized aggregation, but a clean multi-tool dedup proof would require re-importing the missing Lab 4 SCA reports or converting the ZAP report into a parser-supported format.

## Task 2: Governance Report

### Executive Summary
Juice Shop, scanned across the imported DefectDojo tests, currently has `146` open findings: `5` Critical, `56` High, `82` Medium, `1` Low, and `2` Info. No findings were mitigated in this local capstone run yet, so MTTR is not established from closed items. The current backlog is entirely same-day (`2026-07-10`) and therefore newly detected rather than aged debt.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 56 |
| Medium | 82 |
| Low | 1 |
| Info | 2 |

### Findings by source tool

| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Checkov Scan | 80 | 0 | 0 | 0 |
| KICS Scan (Ansible) | 10 | 0 | 0 | 0 |
| KICS Scan (Pulumi) | 6 | 0 | 0 | 0 |
| Trivy Scan | 50 | 0 | 0 | 0 |
| Semgrep Pro JSON Report | Imported, no direct finding count visible in final per-test snapshot | 0 | 0 | 0 |
| Trivy Operator Scan | Imported, but not reflected as separate count in final per-test snapshot | 0 | 0 | 0 |
| ZAP Scan | 0 (parser mismatch on JSON input) | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): `0` days in this capstone import run, because all currently active findings were created/imported on `2026-07-10`
- **MTTR** (Mean Time to Remediate): `N/A` — no mitigated findings yet
- **Vuln-age median** (open findings): `0` days
- **Backlog trend**: `+146` findings versus an empty baseline product
- **SLA compliance**: effectively `100%` at import time because none of the active findings were overdue during the same-day ingestion window

### Risk-accepted items (must have expiry)
No findings were marked as Risk Accepted in this local capstone run, so there are no active risk acceptance expiries to track yet.

### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)
The next concrete maturity step would be **Defect Management / Unified Policy-Driven Intake**: restore the missing Lab 4 SCA reports, convert unsupported ZAP JSON into a parser-supported format, and ingest Falco runtime findings through a custom parser or normalized intermediary. That would improve cross-tool correlation quality and make the DefectDojo dataset closer to a production-grade vulnerability program rather than a point-in-time lab aggregation.

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: `4:30` target script length
- Two anticipated Q&A questions covered: `yes`
- Strongest claim in the script (most-quoted-by-interviewer line, in your view): `I did not stop at running scanners; I normalized the outputs into a single vulnerability-management program with prioritization and response metrics.`
