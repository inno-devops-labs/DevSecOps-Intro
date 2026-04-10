# Metrics Snapshot — Lab 10

- Date captured: 2026-04-10
- Active findings:
  - Critical: 2
  - High: 11
  - Medium: 4
  - Low: 3
  - Informational: 3
- Total active findings: 23
- Verified vs. Mitigated notes: All 23 findings are active and unverified (imported fresh, no triage done yet). Zero findings mitigated at time of snapshot. No findings marked as false positive or out of scope.

## Findings by Tool

| Tool            | Findings |
|----------------|----------|
| ZAP Scan        | 5        |
| Semgrep         | 5        |
| Trivy Scan      | 5        |
| Nuclei Scan     | 5        |
| Anchore Grype   | 3        |
| **Total**       | **23**   |

## SLA Notes

- No findings have been open long enough to breach SLA (all were imported today, 2026-04-10).
- Critical findings (2): @babel/traverse CVE-2023-45133 (CVSS 9.3) and sequelize CVE-2023-49085 (CVSS 9.8) — both from dependency scanning (Trivy/Grype). These should be patched within 7 days per a typical critical SLA.
- No items due within the next 14 days based on current SLA configuration (SLA start = import date).

## Top CWE Categories

- CWE-89 (SQL Injection) — found by Semgrep, Nuclei, Trivy
- CWE-79 (XSS) — found by ZAP, Semgrep
- CWE-347 (Improper Signature Verification / JWT) — found by Semgrep, Nuclei
- CWE-798 (Hardcoded Credentials) — found by Semgrep
- CWE-122 / CWE-400 (Buffer Overflow / Resource Exhaustion) — found by Trivy (OS packages)
