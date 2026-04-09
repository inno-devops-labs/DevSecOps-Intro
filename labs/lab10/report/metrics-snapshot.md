# Metrics Snapshot — Lab 10

- Date captured: 2026-04-09 (API export from engagement **Labs Security Testing**, product **Juice Shop**)
- Engagement ID: 1
- Total imported findings (all active): **292**

## Active findings by severity

| Severity   | Count |
| ---------- | ----: |
| Critical   |    21 |
| High       |   152 |
| Medium     |    86 |
| Low        |    21 |
| Info       |    12 |

## Verified vs. mitigated (program hygiene)

- **Verified:** 143 findings marked verified; **149** not verified (work remaining for validation workflow).
- **Mitigated:** 0 mitigated in this snapshot; all 292 remain **active** for triage/remediation tracking.

## Findings per scan (test)

| Tool / scan type           | Test ID | Findings |
| -------------------------- | ------- | -------: |
| ZAP Scan                   | 1       |        0 (import failed — JSON not accepted; see submission) |
| Semgrep JSON Report        | 2       |       25 |
| Trivy Scan                 | 3       |      147 |
| Anchore Grype              | 4       |      120 |

## SLA outlook (from API fields)

- **SLA breaches (past due):** 0
- **Due within next 14 days** (`sla_days_remaining` ≤ 14): **21** findings (all share expiration **2026-04-16** in this dataset)
- Other grouped expiration buckets include **2026-05-09** (152), **2026-07-08** (86), **2026-08-07** (21).

## Top recurring CWEs (excluding 0 / unset)

1. **CWE-1333** — 29 (e.g. ReDoS-related patterns in dependency reports)
2. **CWE-407** — 13
3. **CWE-22** — 11 (path traversal class)
4. **CWE-79** — 11 (XSS class)
5. **CWE-20** — 6 (input validation)

*Note: CWE `0` appears on 135 items (scanner did not map a CWE).*
