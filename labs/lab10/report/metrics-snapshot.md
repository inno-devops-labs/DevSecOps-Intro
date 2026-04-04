# Metrics Snapshot — Lab 10

- Date: 2026-04-03  
- Dojo: `http://localhost:8080`  
- Engineering / **Juice Shop** / **Labs Security Testing**

## By severity (whole engagement)

From `findings.csv` after imports.

| Severity | Count |
| -------- | ----:|
| Critical | 84 |
| High | 602 |
| Medium | 314 |
| Low | 102 |
| Informational | 61 |
| **Total** | **1163** |

## Status

- Active: 1163  
- Verified: 572 / not verified: 591  
- Mitigated: 0 at this point  

Nothing was closed yet — I’d just finished importing.

## Last batch only (tests 16–20)

| Tool | Scan type | Findings |
| ---- | --------- | -------:|
| ZAP | ZAP Scan | 11 |
| Semgrep | Semgrep JSON Report | 25 |
| Trivy | Trivy Scan | 147 |
| Nuclei | Nuclei Scan | 1 |
| Grype | Anchore Grype | 122 |
| | **Sum** | **306** |

1163 > 306 because I ran imports several times and didn’t turn on `close_old_findings`; old tests are still there. Delete them in Dojo if you want a clean total.

## CWE (top 5)

| CWE | ~count |
| --- | -----:|
| 1333 | 116 |
| 407 | 52 |
| 22 | 44 |
| 79 | 30 |
| 20 | 24 |

## SLA

84 findings with ≤14 days SLA remaining. Dates are in `findings.csv`.
