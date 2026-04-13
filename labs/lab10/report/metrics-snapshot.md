# Metrics Snapshot — Lab 10

## Overview
- **Date:** April 13, 2026

## Active Findings Summary

### By Severity
- **Critical:** 21 findings requiring immediate attention
- **High:** 145 findings requiring prompt remediation
- **Medium:** 68 findings for scheduled remediation
- **Low:** 21 findings for backlog consideration
- **Informational:** 13 findings for awareness
- **Total Active Findings:** 268

### By Tool
- **ZAP (DAST):** 0 findings (import failed - requires XML format, not JSON)
- **Semgrep (SAST):** 0 findings (format compatibility issue)
- **Trivy (Container/Dependency Scan):** 147 findings (10 Critical, 83 High, 36 Medium, 18 Low, 0 Info)
- **Nuclei (Vulnerability Scan):** 1 finding (0 Critical, 0 High, 0 Medium, 0 Low, 1 Info)
- **Grype (Container/Dependency Scan):** 120 findings (11 Critical, 62 High, 32 Medium, 3 Low, 12 Info)

## Finding Status Distribution

### Status Breakdown
- **Active:** 268 findings awaiting triage/remediation
- **Verified:** 143 findings confirmed as true positives (primarily from Trivy)
- **Mitigated:** 0 findings (no remediation completed yet)
- **False Positive:** 0 findings
- **Risk Accepted:** 0 findings

### Notes on Verified vs. Mitigated
- New imports default to "Active" status
- Trivy automatically marked 143 findings as "Verified" during import
- After review, findings should be marked "Verified" if confirmed as true positives
- Once remediated, findings should transition to "Mitigated" status
- Current state reflects initial import with minimal manual triage
- Grype and Nuclei findings remain in "Active" status pending security team review

## SLA Compliance

### Due Dates & Priorities
Based on standard SLA policy (Critical: 7 days, High: 30 days, Medium: 90 days):
- **Overdue Critical:** 0 (all just imported)
- **Overdue High:** 0 (all just imported)
- **Due in next 14 days:** 21 Critical findings (require immediate action within 7 days)
- **Due in next 30 days:** 145 High severity findings
- **Within SLA:** 89 Medium/Low/Info findings

### SLA Notes
- All findings were imported on April 13, 2026
- Critical findings (21) should be triaged by April 20, 2026
- High severity findings (145) should be addressed by May 13, 2026
- No SLA configuration has been set in DefectDojo yet - recommend configuring under System Settings
- Current metrics assume standard industry SLA timelines

## Top Vulnerability Categories

### By CWE Classification
1. **CWE-1333: Inefficient Regular Expression Complexity** - 29 occurrences (ReDoS vulnerability)
2. **CWE-407: Algorithmic Complexity** - 13 occurrences (DoS via CPU exhaustion)
3. **CWE-22: Path Traversal** - 11 occurrences (Directory traversal vulnerabilities)
4. **CWE-20: Improper Input Validation** - 6 occurrences
5. **CWE-674: Uncontrolled Recursion** - 6 occurrences
6. **CWE-1321: Improperly Controlled Modification of Object Prototype Attributes** - 6 occurrences (Prototype Pollution)
7. **CWE-400: Uncontrolled Resource Consumption** - 5 occurrences
8. **CWE-79: Cross-site Scripting (XSS)** - 4 occurrences
9. **CWE-248: Uncaught Exception** - 4 occurrences
10. **Unspecified CWE** - 135 findings (package vulnerabilities without specific CWE mapping)

### By OWASP Top 10 (2021)
Based on the CWE mappings above:
1. **A03:2021 – Injection** - CWE-79 (XSS), CWE-22 (Path Traversal), CWE-20 (Input Validation)
2. **A06:2021 – Vulnerable and Outdated Components** - Most findings are CVEs in npm packages
3. **A05:2021 – Security Misconfiguration** - CWE-248 (Uncaught exceptions), CWE-20 (Input validation)
4. **A04:2021 – Insecure Design** - CWE-400, CWE-407 (Resource consumption issues)

## Import Summary

### Import Statistics
- **Total reports imported:** 5 (ZAP, Semgrep, Trivy, Nuclei, Grype)
- **Successful imports:** 3 (Trivy, Nuclei, Grype)
- **Failed imports:** 2 (ZAP requires XML format; Semgrep format compatibility issue)
- **Total findings created:** 268 findings
- **Deduplication applied:** Yes (default DefectDojo deduplication algorithm)
- **Import date:** April 13, 2026

### Per-Tool Import Results
1. **ZAP Scan** - FAILED: Error "Wrong file format, please use xml" - The zap-report-noauth.json is in JSON format but DefectDojo's ZAP importer requires XML format
2. **Semgrep Pro JSON Report** - PARTIAL: Import completed but 0 findings detected - potential format compatibility issue
3. **Trivy Scan** - SUCCESS: 147 findings imported (10 Critical, 83 High, 36 Medium, 18 Low)
4. **Nuclei Scan** - SUCCESS: 1 finding imported (1 Info)
5. **Anchore Grype** - SUCCESS: 120 findings imported (11 Critical, 62 High, 32 Medium, 3 Low, 12 Info)

## Recommendations

Based on the metrics snapshot:
1. **Immediate Action:** Address all Critical and High severity findings within defined SLA
2. **Triage Process:** Review Active findings and mark as Verified or False Positive
3. **Remediation Priority:** Focus on verified critical/high findings with shortest SLA
4. **False Positive Review:** Document justification for any FP markings
5. **Tracking:** Set up recurring reports to monitor progress week-over-week

## Artifacts Generated
- ✓ This metrics snapshot: `labs/lab10/report/metrics-snapshot.md`
- ⏳ DefectDojo report (PDF/HTML): `labs/lab10/report/dojo-report.(pdf|html)` - Generate from UI
- ⏳ Findings CSV export: `labs/lab10/report/findings.csv` - Export from engagement page
- ⏳ Import response files: `labs/lab10/imports/import-*.json`
