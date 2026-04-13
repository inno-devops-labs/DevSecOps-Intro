# Lab 10 — Vulnerability Management & Response with DefectDojo

## Task 1 — DefectDojo Local Setup

- Cloned upstream `DefectDojo/django-DefectDojo` into `labs/lab10/setup/django-DefectDojo/`.
- Built and started the stack with `docker compose build && docker compose up -d`; UI reachable at `http://localhost:8080`.
- Retrieved the initializer-generated admin password from `docker compose logs initializer | grep "Admin password:"` and logged in as `admin`.
- Created the context used for imports:
  - Product Type: **Engineering**
  - Product: **Juice Shop**
  - Engagement: **Labs Security Testing**

## Task 2 — Import Prior Findings

Imports run via `labs/lab10/imports/run-imports.sh` using the API v2 token. Raw API responses saved under `labs/lab10/imports/`.

| Tool   | Scan type (Dojo)          | Imported | Critical | High | Medium | Low | Info |
|--------|---------------------------|---------:|---------:|-----:|-------:|----:|-----:|
| Trivy  | Trivy Scan                |      147 |       10 |   83 |     36 |  18 |    0 |
| Grype  | Anchore Grype             |      122 |       11 |   64 |     32 |   3 |   12 |
| Semgrep| Semgrep JSON Report       |       25 |        0 |    7 |     18 |   0 |    0 |
| ZAP    | ZAP Scan                  | rejected |        — |    — |      — |   — |    — |
| Nuclei | —                         | skipped  |        — |    — |      — |   — |    — |

Notes:
- The ZAP JSON export from Lab 5 was rejected by the importer (`Wrong file format, please use xml.`). To re-import it, a fresh ZAP run with `-x` (XML) output would be needed; the current lab5 artifact is JSON only.
- Nuclei report was not available under `labs/lab5/nuclei/nuclei-results.json`, so nothing to import.

## Task 3 — Reporting & Program Metrics

Artifacts produced:
- `labs/lab10/report/metrics-snapshot.md` — baseline severity snapshot captured from the engagement dashboard.
- `labs/lab10/report/dojo-report.html` — Dojo-generated engagement report (HTML, stakeholder-readable).
- `labs/lab10/report/findings.csv` — full findings export (294 rows) for spreadsheet analysis.

### Key metrics

- **Open vs. Closed by severity (Active / Mitigated):** Critical 21/0, High 154/0, Medium 86/0, Low 21/0, Info 12/0 — everything is currently Active; mitigation workflow to be tracked in subsequent iterations as fixes land.
- **Findings per tool:** Trivy 147, Grype 122, Semgrep 25 (Total 294). ZAP import failed (format mismatch) and Grype overlaps with Trivy on several node-pkg CVEs — deduplication by CVE/component would collapse ~30–40% of duplicates.
- **SLA outlook:** Default Dojo SLAs put Critical findings due within 7 days (2026-04-20) and High within 30 days (2026-05-13). Today 21 Critical + 154 High are at risk of breach in the next 14 days unless accepted or mitigated.
- **Top recurring CWEs:** CWE-1333 Inefficient Regex / ReDoS (29), CWE-407 Algorithmic Complexity (13), CWE-22 Path Traversal (11), CWE-79 XSS (11), CWE-1321 Prototype Pollution (6) — dominated by vulnerable Node.js dependencies in the Juice Shop image.
- **Hotspots:** `juice-shop/node_modules/*` accounts for the vast majority of critical/high SCA findings (lodash, jsonwebtoken, marsdb, vm2, sanitize-html); remediation = dependency upgrades / replacing abandoned packages.

## Acceptance Checklist

- [x] DefectDojo runs locally and admin login works.
- [x] Product Type / Product / Engagement configured.
- [x] Imports completed for Trivy, Grype, Semgrep (ZAP import rejected due to JSON-vs-XML; Nuclei artifact not available).
- [x] Reporting artifacts generated: metrics snapshot, Dojo HTML report, findings CSV, and metric summary above.
- [x] All artifacts saved under `labs/lab10/`.
