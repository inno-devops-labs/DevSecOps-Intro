## Active Findings by Severity

| Severity      |   Count |
|---------------|--------:|
| Critical      |      21 |
| High          |     155 |
| Medium        |      89 |
| Low           |      28 |
| Informational |      20 |
| **Total**     | **313** |

---

## Findings Status

| Status       | Count |
|--------------|------:|
| Active       |   313 |
| Verified     |   143 |
| Mitigated    |     0 |
| False Pos.   |     0 |
| Out of Scope |     0 |

---

## Findings per Tool

| Test ID | Tool                 | Findings |
|--------:|----------------------|---------:|
|       6 | ZAP Scan             |       12 |
|       2 | Semgrep JSON Report  |       25 |
|       3 | Trivy Scan           |      147 |
|       4 | Nuclei Scan          |        7 |
|       5 | Anchore Grype        |      122 |
|         | **Total**            |  **313** |

> Test 1 (ZAP Scan) was an initial empty run; all 12 ZAP findings are in Test 6.

---

## Top CWE Categories

| CWE      | Count | Description                                       |
|----------|------:|---------------------------------------------------|
| CWE-0    |   145 | No CWE assigned (Trivy/Grype package vulns)       |
| CWE-1333 |    29 | Inefficient Regular Expression Complexity (ReDoS) |
| CWE-407  |    13 | Algorithmic Complexity                            |
| CWE-79   |    11 | Cross-site Scripting (XSS)                        |
| CWE-22   |    11 | Path Traversal                                    |
| CWE-89   |     6 | SQL Injection                                     |
| CWE-20   |     6 | Improper Input Validation                         |
| CWE-1321 |     6 | Prototype Pollution                               |
| CWE-674  |     6 | Uncontrolled Recursion                            |
| CWE-400  |     5 | Uncontrolled Resource Consumption                 |

---

## Verified vs. Mitigated Notes

- **143 findings are verified** - all come from the Trivy Scan,
  which DefectDojo auto-verified because the Trivy parser marks CVEs with known exploits as verified.
- **0 findings mitigated** - no patches or remediation actions have been applied yet in this
  engagement; all findings remain open from the initial import.
- **SLA outlook:** With default SLA settings (Critical = 7 days, High = 30 days, Medium = 90 days,
  Low = 180 days), the 21 Critical findings are already within the SLA breach window if not
  remediated by 2026-04-16. The 155 High findings are due by 2026-05-09.
- **No deduplication** was applied across tools; cross-tool duplicates may be present and inflate total counts.
