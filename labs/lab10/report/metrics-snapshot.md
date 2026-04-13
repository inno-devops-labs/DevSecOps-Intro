# Metrics Snapshot — Lab 10

- Date captured: April 13, 2026
- Active findings:
  - Critical: 21
  - High: 153
  - Medium: 77
  - Low: 26
  - Informational: 17
- **Total active findings: 294**
- Verified findings: 143 (all from Trivy — auto-verified by the importer)
- Mitigated findings: 0 (this is the initial baseline import)

## Findings by Tool

| Tool    | Findings | Share  |
| ------- | -------: | -----: |
| ZAP     |        9 |   3.1% |
| Semgrep |        8 |   2.7% |
| Trivy   |      147 |  50.0% |
| Nuclei  |        8 |   2.7% |
| Grype   |      122 |  41.5% |

## Top CWE Categories

| CWE                                | Count |
| ---------------------------------- | ----: |
| CWE-1333: ReDoS                    |    29 |
| CWE-407: Algorithmic Complexity    |    13 |
| CWE-22: Path Traversal            |    12 |
| CWE-79: XSS                       |     6 |
| CWE-20: Improper Input Validation |     6 |
| CWE-674: Uncontrolled Recursion   |     6 |
| CWE-1321: Prototype Pollution     |     6 |
| CWE-400: Resource Consumption     |     5 |
| CWE-94: Code Injection            |     4 |

## Notes

- DefectDojo's default deduplication algorithm is used (hash-based on title + CWE + file_path for SAST, title + endpoints for DAST).
- Trivy and Grype have overlapping coverage on container image vulnerabilities; some duplicates are expected across tools but counted separately since they come from different test types.
- No SLA policies have been configured yet; all 21 Critical findings would breach a standard 7-day SLA if left unaddressed beyond April 20, 2026.

