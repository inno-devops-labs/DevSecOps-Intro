# Lab 10 — Vulnerability Management & Response with DefectDojo

## Goal
The goal of this lab was to deploy OWASP DefectDojo locally, import findings from previous labs, and generate a consolidated vulnerability management view with reporting and metrics artifacts.

## Task 1 — DefectDojo Local Setup
DefectDojo was deployed locally using Docker Compose from the upstream `django-DefectDojo` repository.

### Completed steps
- Cloned DefectDojo into `labs/lab10/setup/django-DefectDojo`
- Verified Docker Compose compatibility
- Built and started the stack with Docker Compose
- Verified running containers with `docker compose ps`
- Opened the UI successfully in the browser

### Environment adjustments
There were local port conflicts on the host:
- `8080` was already occupied
- `8443` was already occupied

To resolve this, the following overrides were added in `.env`:
- `DD_PORT=8081`
- `DD_TLS_PORT=8444`

After reconfiguration, DefectDojo became accessible at:
- `http://localhost:8081`

## Task 2 — Import Prior Findings
The required scan artifacts were imported into DefectDojo under the following context:
- Product Type: `Engineering`
- Product: `Juice Shop`
- Engagement: `Labs Security Testing`

### Import workflow
The provided script `labs/lab10/imports/run-imports.sh` was used for the main imports.

### Imported tools
- **Semgrep** — imported from `labs/lab5/semgrep/semgrep-results.json`
- **Trivy** — imported from `labs/lab4/trivy/trivy-vuln-detailed.json`
- **Nuclei** — imported from `labs/lab5/nuclei/nuclei-results.json`
- **Grype** — imported from `labs/lab4/syft/grype-vuln-results.json`

### ZAP import note
The initial scripted ZAP import failed because the DefectDojo importer expected XML rather than JSON.  
To resolve this:
- ZAP was opened manually
- a fresh scan against `http://localhost:8081` was executed
- a valid XML report was generated as `labs/lab10/imports/zap-real.xml`
- the ZAP XML report was imported successfully through the DefectDojo API

## Task 3 — Reporting & Metrics

### Metrics snapshot
The engagement dashboard showed the following aggregated active findings:

- Critical: **21**
- High: **109**
- Medium: **68**
- Low: **21**
- Informational: **27**
- Total Findings: **246**

### Findings per tool
From the engagement test list:
- Anchore Grype: **109**
- Nuclei Scan: **12**
- Semgrep Pro JSON Report: **0**
- Trivy Scan: **120**
- ZAP Scan: **5**

### Verified / Mitigated status
At this stage, findings represent aggregated scan results from multiple tools. Verification and mitigation workflows have not yet been performed, as the focus of this lab is on centralized import and visibility of vulnerabilities within DefectDojo.

### SLA / due items
No SLA remediation workflow was configured during this lab. The environment was used to aggregate, import, and review scan results rather than to manage remediation deadlines.

### Top recurring categories
The dominant risk picture is driven by dependency and package vulnerabilities imported from Trivy and Grype. High and Medium severities make up the largest portion of the results, indicating that dependency remediation would provide the biggest immediate security impact.

## Deliverables
Created artifacts for this lab include:
- `labs/lab10/report/metrics-snapshot.md`
- `labs/lab10/report/dojo-report.html`
- `labs/lab10/report/findings.csv`
- import responses saved under `labs/lab10/imports/`
- ZAP XML artifact saved as `labs/lab10/imports/zap-real.xml`

## Summary
This lab demonstrated how DefectDojo can be used as a centralized vulnerability management platform. Findings from multiple scanners were imported into a single engagement, aggregated, and reviewed through one dashboard. The final result was a unified view of 246 findings across the imported tools, with High severity findings forming the largest group.
