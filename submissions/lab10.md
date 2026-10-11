# Lab 10 — Submission



## Task 1: DefectDojo Setup + Import



### DefectDojo version

- Version installed: v2.58.x (latest)



### Product + Engagement

- Product ID: 1

- Product name: OWASP Juice Shop

- Engagement ID: 1

- Engagement status: In Progress



### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 106 |
| 4 | Trivy Scan | trivy.json | 109 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | zap-report-auth.json | 12 |
| 6 | Checkov Scan | results\_json.json | 78 |
| 6 | KICS Scan | kics-ansible/results.json | 4 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 48 |
| \*\*Total raw imports\*\* | | | 385 |
| \*\*After dedup\*\* | | | 281 |



### Dedup example (Lecture 10 slide 11)

- CVE/ID: CVE-2023-46233 (crypto-js)

- Number of source tools: 3 (Trivy image, Trivy k8s, Grype)

- DefectDojo's single finding ID: (Deduplicated into a single active finding in the dashboard)



---



## Task 2: Governance Report



### Executive Summary

Juice Shop, scanned across 9 tools, currently has 281 open findings (5 Critical + 43 High). Mean Time to Remediate (MTTR) on closed-this-period findings is 0 days (none closed yet). 0% of findings closed within their SLA, highlighting the need for immediate remediation sprint.



### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 5 |
| High | 43 |
| Medium | 39 |
| Low | 22 |
| \*\*Total\*\* | 281 (includes Info/Unspecified) |



### Findings by source tool

| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Trivy | 109 | 0 | 0 | 0 |
| Grype | 106 | 0 | 0 | 0 |
| Semgrep | 22 | 0 | 0 | 0 |
| ZAP | 12 | 0 | 0 | 0 |
| Checkov | 78 | 0 | 0 | 0 |
| KICS | 10 | 0 | 0 | 0 |



### Program metrics

- \*\*MTTD\*\* (Mean Time to Detect): 0 days (scans run in CI/CD)

- \*\*MTTR\*\* (Mean Time to Remediate): N/A days (no findings closed yet)

- \*\*Vuln-age median\*\* (open findings): 1 day

- \*\*Backlog trend\*\*: Stable (initial baseline run)

- \*\*SLA compliance\*\*: 0% (SLA matrix applied, remediation pending)



### Risk-accepted items (must have expiry)

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| (None risk-accepted in this lab run) | - | - | - |



### Next-quarter goal (OWASP SAMM ladder step — Lecture 9 slide 15)

"Defect Management — current MTTR for High is undefined (0 closed); I would mature this by enforcing SLA breach alerts in DefectDojo and automating JIRA ticket creation for any Critical/High finding older than 24 hours/7 days respectively."



---



## Bonus: Interview Walkthrough



- Walkthrough script: see `submissions/lab10-walkthrough.md`

- Practiced runtime: 4:45

- Two anticipated Q\&A questions covered: yes

- Strongest claim in the script: "The strongest correlated finding was SQL Injection... caught by both Semgrep and ZAP, which gave us high confidence to prioritize the fix."

