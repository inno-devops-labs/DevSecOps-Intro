# Metrics Snapshot — Lab 10

- Date captured: 2026-04-13
- Engagement: Labs Security Testing
- Product: Juice Shop (bkimminich/juice-shop:v19.0.0)

## Active findings by severity

| Severity     | Count |
|--------------|------:|
| Critical     |    22 |
| High         |   201 |
| Medium       |   136 |
| Low          |    39 |
| Info         |    18 |
| **Total**    | **416** |

## Active findings by tool

| Tool    | Findings | scan_type             |
|---------|----------|-----------------------|
| Trivy   |      198 | Trivy Scan            |
| Grype   |      167 | Anchore Grype         |
| Semgrep |       39 | Semgrep JSON Report   |
| ZAP     |       12 | ZAP Scan (XML)        |
| Nuclei  |        0 | Nuclei Scan           |

## Top CWE categories

| CWE      | Description                                  | Count |
|----------|----------------------------------------------|------:|
| CWE-1333 | Inefficient Regular Expression (ReDoS)       |    34 |
| CWE-400  | Uncontrolled Resource Consumption            |    17 |
| CWE-22   | Path Traversal                               |    17 |
| CWE-407  | Inefficient Algorithmic Complexity           |    13 |
| CWE-79   | Cross-Site Scripting (XSS)                   |    11 |
| CWE-1321 | Prototype Pollution                          |    10 |
| CWE-20   | Improper Input Validation                    |     8 |
| CWE-89   | SQL Injection                                |     7 |

## Verified vs. Mitigated notes

- 416 findings active, 0 mitigated at snapshot time.
- Trivy-imported findings were auto-verified (194 of 198) because Trivy provides CVE-based evidence.
- Grype and Semgrep findings are active but unverified — require manual triage.
- No SLA deadlines configured; all findings are within the default 30-day engagement window (ends 2026-05-13).
- Nuclei produced 0 findings because the scan ran without template updates against the local instance; templates matched 0 active rules for this target.
