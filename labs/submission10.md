# Lab 10 — Vulnerability Management with DefectDojo

## Setup Evidence
DefectDojo is running locally via Docker Compose.
- UI: http://localhost:8080
- Status: 7 containers running and healthy.

## Import Results
Security findings from previous labs were imported using a custom PowerShell script (`run-imports.ps1`):
- **Semgrep Sast**: Success (147 findings total across related tests)
- **Nuclei Dast**: Success (25 findings, converted from JSON-L)
- **Trivy Container Scan**: Success (122 findings from `juice-shop-trivy-detailed.json`)
- **Anchore Grype**: Success (122 findings)
- **OWASP ZAP**: Skipped (report not found in `labs/lab5/zap/`)

## Metrics Highlights
- **Total Active Findings**: 710
- **Severity Mix**:
  - Critical: 53
  - High: 372
  - Medium: 204
  - Low: 45
  - Info: 36
- **Tool Distribution**: Largest volume of findings coming from Semgrep and Trivy/Grype.
- **SLA Status**: Most findings have a 90-day SLA. Some items from Nuclei show shorter timelines (7-14 days).
