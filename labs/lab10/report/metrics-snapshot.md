# Metrics Snapshot — Lab 10

- Date captured: 2026-04-13
- Active findings:
  - Critical: 24
  - High: 211
  - Medium: 150
  - Low: 45
  - Informational: 27
- Total active findings: 457
- Verified vs. Mitigated notes: 194 findings (Trivy Scan) were auto-verified on import. All remaining findings are in Active status pending triage. No findings have been mitigated yet as this is the initial import baseline.

## Findings per Tool

| Scanner             | Findings |
|---------------------|----------|
| ZAP Scan            | 9        |
| Semgrep JSON Report | 39       |
| Trivy Scan          | 194      |
| Nuclei Scan         | 10       |
| Anchore Grype       | 167      |
| **Total**           | **457**  |

Note: Some findings overlap between Trivy and Grype as both perform SCA on the same image. DefectDojo deduplication was not applied across different scan types.

## Top CWE Categories

| CWE    | Description                                              | Count |
|--------|----------------------------------------------------------|-------|
| CWE-1333 | Inefficient Regular Expression Complexity (ReDoS)      | 35    |
| CWE-22   | Path Traversal                                         | 18    |
| CWE-400  | Uncontrolled Resource Consumption                      | 18    |
| CWE-79   | Cross-Site Scripting (XSS)                             | 13    |
| CWE-407  | Inefficient Algorithmic Complexity                     | 13    |
| CWE-200  | Information Exposure                                   | 10    |
| CWE-1321 | Prototype Pollution                                    | 10    |
| CWE-89   | SQL Injection                                          | 9     |
| CWE-693  | Protection Mechanism Failure                           | 9     |

## SLA Status

- No SLA policies are currently configured in this DefectDojo instance.
- Recommendation: Set Critical findings SLA to 7 days, High to 30 days, Medium to 90 days, Low to 180 days.
- At current state, 235 findings (Critical + High) would require priority triage.
