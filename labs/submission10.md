# Lab 10 — Vulnerability Management & Response with DefectDojo

## Task 1 — DefectDojo Local Setup

### Setup summary
DefectDojo was deployed locally using Docker Compose and accessed via `http://localhost:8080`.

### Evidence
- DefectDojo repository cloned into `labs/lab10/setup/django-DefectDojo`
- Services started successfully with Docker Compose
- Admin access was confirmed using the password printed by the `initializer` logs
- API access was configured with a valid API v2 token

### Structure created
- Product Type: Engineering
- Product: Juice Shop
- Engagement: Labs Security Testing

---

## Task 2 — Import Prior Findings

### Import approach
The original lab artifacts were partially unavailable, so the workflow used:
- locally generated Grype results from a Syft SBOM
- sample reports for Semgrep and Trivy

This allowed full validation of the DefectDojo workflow.

### Imported scan sources
- Grype: `labs/lab10/imports/source-reports/grype-results.json`
- Semgrep: `labs/lab10/imports/source-reports/semgrep-results.json`
- Trivy: `labs/lab10/imports/source-reports/trivy-results.json`

### Import execution
```bash
bash labs/lab10/imports/run-imports.sh
```

## Results

Semgrep imported successfully (5 findings)

Anchore Grype imported successfully (167 findings)

Trivy import failed with internal server error (documented)

## Task 3 — Reporting & Metrics

### Generated artifacts

metrics snapshot: labs/lab10/report/metrics-snapshot.md
report: labs/lab10/report/dojo-report.pdf
findings export: labs/lab10/report/findings.csv

### Metrics summary

Total findings: 179
Critical: 11
High: 88
Medium: 56
Low: 8
Informational: 16

### Analysis

Majority of vulnerabilities come from dependency scanning (Grype)
Semgrep identified code-level issues (medium severity)
High and Medium vulnerabilities dominate the risk profile

### Conclusion

DefectDojo successfully centralized vulnerability findings from multiple tools into a single platform. The workflow demonstrated scan import, vulnerability aggregation, and reporting. The generated metrics and reports provide a clear overview for prioritization and remediation planning.
