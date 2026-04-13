# Lab 10 — Vulnerability Management & Response with DefectDojo

## Goal
The goal of this lab is to set up a local instance of OWASP DefectDojo, import vulnerability scan results from multiple security tools (ZAP, Semgrep, Trivy, Nuclei, and Grype), and generate a stakeholder-ready reporting and metrics package.  
This demonstrates the ability to aggregate findings, manage them across engagements, and communicate program status using metrics and reports.

## Setup Summary
DefectDojo was deployed locally using Docker Compose (`labs/lab10/setup/django-DefectDojo`).  
The admin credentials were retrieved from the initializer logs, and the dashboard was successfully accessed at `http://localhost:8080`.  
A new Product Type (**Engineering**), Product (**Juice Shop**), and Engagement (**Labs Security Testing**) were created to store imported results.

## Imports Overview
Scan results were imported using the automated script `labs/lab10/imports/run-imports.sh` with the API v2 endpoint.  
Each JSON report was mapped to its respective importer:

| Tool | Scan type in Dojo | Findings imported | Notes |
|------|--------------------|------------------:|-------|
| ZAP | OWASP ZAP JSON | 0 | Wrong format (expected XML) |
| Semgrep | Semgrep Pro JSON Report | 0 | No findings in this run |
| Trivy | Trivy Scan | 74 | Critical: 9, High: 28, Medium: 33, Low: 4 |
| Nuclei | Nuclei Scan | 3 | Informational level detections |
| Grype | Anchore Grype | 65 | Critical: 8, High: 21, Medium: 23, Low: 1, Info: 12 |

All imports completed successfully except ZAP (JSON format not supported in the community importer).  
Combined, these sources contributed over 140 active findings across different severity levels.

## Metrics Snapshot
```
- Date captured: 12.11.2025
- Active findings:
  - Critical: 17
  - High: 49
  - Medium: 56
  - Low: 5
  - Informational: 15
- Verified vs. Mitigated notes: All imported findings are in “Verified” state (no mitigations performed in this lab). Mitigation process will follow in later remediation phase.
```

## Key Metrics and Observations
- **Open vs. Closed:** All 142 findings remain open and verified; no mitigated or closed findings yet.  
- **Findings per tool:** Trivy (74) and Grype (65) produced most results, Nuclei added 3 informational detections; ZAP and Semgrep had no actionable issues.  
- **SLA status:** No SLA breaches were observed; all findings are newly imported and within the initial 14-day response window.  
- **Severity distribution:** Critical + High findings account for roughly 46% of all issues, with the remainder mostly Medium-level dependency vulnerabilities.  
- **Top categories:** Most recurring CWE/OWASP patterns include outdated components (CWE-1104), improper input validation (CWE-20), and insecure dependency usage (OWASP A06:2021).  

These metrics indicate that the majority of risks stem from dependency and container image vulnerabilities rather than direct web application logic flaws.
