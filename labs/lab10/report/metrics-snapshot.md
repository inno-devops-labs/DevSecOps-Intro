# Metrics Snapshot — Lab 10

- Date captured: 2026-03-09
- Active findings:
  - Critical: 11
  - High: 62
  - Medium: 38
  - Low: 19
  - Informational: 12
- Total active: 142
- Verified: 0
- Mitigated: 0
- False positives: 0
- Duplicates suppressed: 91 (hash-based deduplication across Trivy and Grype)
- Verified vs. Mitigated notes: All findings remain in Active status since no triage or remediation has been performed yet. The next step would be to verify Critical and High findings and assign SLA deadlines.

## Findings per Tool

| Tool   | Imported | After Dedup | Critical | High | Medium | Low | Info |
|--------|----------|-------------|----------|------|--------|-----|------|
| Trivy  |      116 |         116 |       10 |   55 |     33 |  18 |    0 |
| Grype  |      117 |          89 |       11 |   60 |     31 |   3 |   12 |
| ZAP    |      N/A |         N/A |      N/A |  N/A |    N/A | N/A |  N/A |
| Semgrep|      N/A |         N/A |      N/A |  N/A |    N/A | N/A |  N/A |
| Nuclei |      N/A |         N/A |      N/A |  N/A |    N/A | N/A |  N/A |

> ZAP, Semgrep, and Nuclei were skipped — report files were not present at the expected paths. Only Trivy and Grype results were imported.

## SLA Status

| Severity     | SLA Target | Due Date   | Status    |
|-------------|-----------|------------|-----------|
| Critical    | 7 days    | 2026-03-16 | On track  |
| High        | 30 days   | 2026-04-08 | On track  |
| Medium      | 90 days   | 2026-06-07 | On track  |
| Low         | 180 days  | 2026-09-05 | On track  |
| Informational | No SLA  | —          | —         |

No SLA breaches at this time (day 0 of triage).
