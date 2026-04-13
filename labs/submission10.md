# Lab 10 - Vulnerability Management & Response with DefectDojo

## Task 1 - DefectDojo Setup

DefectDojo was deployed locally using Docker Compose.

Steps performed:
- Cloned the repository: `git clone https://github.com/DefectDojo/django-DefectDojo.git`
- Built and started services:
`docker compose build docker compose up -d`
- Verified containers are running using `docker compose ps`
- Retrieved admin credentials from initializer logs
- Successfully logged into UI at `http://localhost:8080`

## Task 2 - Import Findings

API access was configured using a generated API token.

Environment variables: 
```
export DD_API="http://localhost:8080/api/v2"
export DD_TOKEN="`<token>`{=html}"
export DD_PRODUCT_TYPE="Engineering"
export DD_PRODUCT="Juice Shop"
export DD_ENGAGEMENT="Labs Security Testing"
```

Findings from previous labs were imported using the provided script:

`bash labs/lab10/imports/run-imports.sh`

Imported tools:
- ZAP
- Semgrep
- Trivy
- Nuclei

Result:
- Product, engagement, and tests were created automatically
- Findings were successfully visible in the DefectDojo UI

## Task 3 --- Reporting & Metrics

### Metrics Snapshot

-   Critical: 0
-   High: 0
-   Medium: 0
-   Low: 0
-   Informational: 1

### Observations

-   Only one informational finding was detected
-   No high or critical vulnerabilities were identified
-   The finding was produced by Nuclei and related to a publicly exposed     Swagger API endpoint (CWE-200)

### Findings by Tool

-   Nuclei: 1 informational finding
-   ZAP: no findings
-   Semgrep: no findings
-   Trivy: no findings

### Reporting Notes

The DefectDojo UI in this setup did not provide a visible option to
generate built-in PDF or HTML reports as described in the lab
instructions.

Instead:
- Findings were reviewed directly in the UI
- A findings export (report) was generated manually from the Findings view

### Conclusion

DefectDojo was successfully deployed and used to aggregate findings from
multiple security tools.

The platform demonstrated how vulnerabilities can be centralized,
categorized, and analyzed, even when the number of findings is minimal.