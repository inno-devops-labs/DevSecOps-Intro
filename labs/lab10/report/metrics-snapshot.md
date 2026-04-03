# Metrics Snapshot — Lab 10

- Date captured: 2026-04-03
- Active findings:
  - Critical: 21
  - High: 154
  - Medium: 84
  - Low: 28
  - Informational: 18
- Total active: 305
- Verified: 143 (all from Trivy Scan — auto-verified by importer)
- Mitigated: 0

## Findings by Tool

| Tool                    | Active Findings |
|-------------------------|---------------:|
| ZAP (Generic Import)    |             12 |
| Semgrep JSON Report     |             21 |
| Trivy Scan              |            147 |
| Nuclei Scan             |              3 |
| Anchore Grype           |            122 |
| **Total**               |        **305** |

## Top CWEs

| CWE     | Count | Description                                      |
|---------|------:|--------------------------------------------------|
| CWE-1333 |    29 | Inefficient Regular Expression Complexity (ReDoS) |
| CWE-407  |    13 | Inefficient Algorithmic Complexity                |
| CWE-22   |    11 | Path Traversal                                    |
| CWE-79   |     7 | Cross-site Scripting (XSS)                        |
| CWE-20   |     6 | Improper Input Validation                         |
| CWE-89   |     6 | SQL Injection                                     |
| CWE-674  |     6 | Uncontrolled Recursion                            |
| CWE-1321 |     6 | Prototype Pollution                               |
| CWE-400  |     5 | Uncontrolled Resource Consumption                 |
| CWE-73   |     4 | External Control of File Name or Path             |

## Severity Distribution

- Critical findings (21) — primarily from Grype (CVEs in OS/library packages) and Trivy (container image vulns)
- High findings (154) — largest category, driven by Trivy image scan (83) and Grype dependency analysis (64)
- Medium findings (84) — Trivy (36), Grype (32), Semgrep SAST (14), ZAP DAST (2)
- Low findings (28) — Trivy (18), Grype (3), ZAP (6), Nuclei (1)
- Info findings (18) — Grype (12), ZAP (4), Nuclei (2)

## Verified vs. Mitigated Notes

143 findings from the Trivy Scan import were auto-verified by the importer based on CVE match confidence. No findings have been mitigated yet — this is the initial baseline import. All other tool imports (Semgrep, Nuclei, Grype, ZAP) produced unverified findings pending manual triage.
