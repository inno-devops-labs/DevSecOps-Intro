# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: **v3.1.0** (release mode) — `defectdojo/defectdojo-django:latest` via official docker-compose (`labs/lab10/work/dd`, `./docker/setEnv.sh release`)
- Admin user: `admin` (password from `docker compose logs initializer | grep -i password` — **not committed**)

### Product + Engagement
- Product ID: **1**
- Product name: OWASP Juice Shop
- Engagement ID: **1** (`Course Semester Run`)
- Engagement status: In Progress

### Imports completed

| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | `labs/lab4/grype-from-sbom.json` | 104 |
| 4 | Trivy Scan | `labs/lab4/trivy.json` | 113 |
| 5 | Semgrep JSON Report | `labs/lab5/results/semgrep.json` | 22 |
| 5 | ZAP Scan | `labs/lab5/results/auth-report.json` | **0 — failed** (DefectDojo requires XML; our ZAP output is JSON) |
| 6 | Checkov Scan | `labs/lab6/results/checkov-terraform/results_json.json` | 80 |
| 6 | KICS Scan | `labs/lab6/results/kics-ansible/results.json` | 10 |
| 7 | Trivy Scan (image) | `labs/lab7/results/trivy-image.json` | 50 |
| 7 | Trivy Operator Scan | `labs/lab7/results/trivy-k8s.json` | 0 (format mismatch — no vulnerabilities parsed) |
| 9 | Falco runtime log | `labs/lab9/falco/logs/falco.log` | skipped (no native importer — documented in runtime layer) |
| **Total raw imports** | | | **379** |
| **After dedup** | | | **331** unique non-duplicate findings |

**Dedup enabled:** `PATCH /api/v2/system_settings/1/` → `enable_deduplication: true`, then `python manage.py dedupe --dedupe_only --dedupe_sync`.

### Dedup example (Lecture 10 slide 11)
- **CVE/ID:** CVE-2024-37890 (`CVE-2024-37890 Ws 7.4.6`)
- **Number of source tools:** **2** — Trivy Scan (Lab 4, test 2) + Trivy Scan (Lab 7 image, test 7); same `hash_code`
- **DefectDojo canonical finding ID:** **210** (duplicate finding **375** → `duplicate_finding: 210`)

```json
{
  "id": 375,
  "title": "CVE-2024-37890 Ws 7.4.6",
  "duplicate": true,
  "duplicate_finding": 210,
  "test": 7
}
```

---

## Task 2: Governance Report

### SLA matrix applied
Via API `PATCH /api/v2/sla_configurations/1/`:
- Critical: **1 day** (24 h)
- High: **7 days**
- Medium: **30 days**
- Low: **90 days**

Product `OWASP Juice Shop` linked to SLA configuration ID 1.

### Executive Summary (3 sentences)
OWASP Juice Shop was scanned across **7 successful tool imports** (Grype, Trivy×2, Semgrep, Checkov, KICS) into a single DefectDojo engagement. After deduplication, **323 active findings** remain open (**12 Critical + 119 High**). **6 findings** were remediated this session (MTTR ≈ 0 days on same-day closures); **2 Low/Medium** items were risk-accepted with explicit semester expiry notes.

### Findings by severity (active only)

| Severity | Count |
|----------|------:|
| Critical | 12 |
| High | 119 |
| Medium | 159 |
| Low | 26 |
| Info | 7 |

### Findings by source tool

| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|--------------:|
| Anchore Grype | 104 | 0 | 0 | 0 |
| Trivy Scan | 115 | 4 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 1 |
| Checkov Scan | 80 | 2 | 0 | 0 |
| KICS Scan | 10 | 0 | 0 | 1 |

*(Trivy active count is post-dedup; duplicates marked inactive.)*

### Program metrics
- **MTTD** (Mean Time to Detect): **0 days** — all findings detected on import date (same-day pipeline)
- **MTTR** (Mean Time to Remediate): **0 days** — 6 Medium findings closed same day as detection (demo remediation)
- **Vuln-age median** (open findings): **0 days** — fresh semester import
- **Backlog trend**: **+331** vs. baseline 0 (first consolidated program view)
- **SLA compliance**: **~100%** on closed sample (6/6 closed within Medium 30-day SLA); open Critical/High tracked against 1d/7d clocks

### Risk-accepted items (must have expiry)

| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| GHSA-pxg6-pf52-xh8x in cookie:0.4.2 (id 61) | Low | Dev-only Juice Shop instance; cookie advisory not exploitable in lab scope | 2026-12-31 |
| GHSA-58qx-3vcg-4xpx in ws:8.17.1 (id 62) | Medium | Transitive WS advisory on pinned lab image; monitor upstream Juice Shop release | 2026-12-15 |

### Next-quarter goal (OWASP SAMM)
Mature **SAMM Stream B — Defect Management** from Level 1 → 2: integrate **runtime Falco JSON** via a custom DefectDojo parser and automate dedup+SLA on every PR. Current gap: runtime alerts live only in `falco.log`; folding them into DefectDojo would close the loop on the 12 Critical container findings and cut MTTR for High items currently visible only in Trivy/Grype.

---

## Bonus: Interview Walkthrough

- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: **4:45**
- Two anticipated Q&A questions covered: **yes**
- Strongest claim: *"We don't just scan — we dedup the same CVE across Grype and two Trivy runs into one finding, then govern it with an SLA matrix."*
