# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Image: `defectdojo/defectdojo-django:latest` (DefectDojo v2.58.x release train)
- Deployed via the upstream compose **release** profile rather than `dev`. On Apple Silicon the `dev`
  profile builds four Django/nginx images from source (very slow on arm64); the release profile pulls
  the published multi-arch images. Ran on the Colima Docker backend (from Lab 9), host port remapped to
  **8081** with `DD_PORT=8081` because Burp Suite already held 8080.

### Product + Engagement
- Product ID: **1**
- Product name: OWASP Juice Shop
- Engagement ID: **1**
- Engagement name: Course Semester Run
- Engagement status: In Progress
- Product type: Engineering
- Created automatically by the importer via `auto_create_context=true`.

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 108 |
| 4 | Trivy Scan | trivy.json (from SBOM) | 80 |
| 5 | Semgrep JSON Report | semgrep.json | 8 |
| 5 | ZAP Scan | auth-report.json | 0 |
| 6 | Checkov Scan | checkov-terraform/results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | SKIPPED — file absent (needs a live cluster; not generated in Lab 7) |
| 8 | — | verify-original.json | NOT IMPORTED — Cosign verify output has no DefectDojo parser; documented instead |
| 9 | — | falco/logs/falco.log | NOT IMPORTED — Falco custom JSON has no built-in parser (lab permits documenting instead) |
| **Total raw imports** | | | **342** |
| **After dedup (active, non-duplicate)** | | | **338 active / 80 flagged duplicate** |

Six distinct scan types were imported (Anchore Grype, Trivy Scan, Semgrep JSON Report, ZAP Scan,
Checkov Scan, KICS Scan), meeting the ≥6 requirement.

**Regeneration note.** The Lab 4 Grype/Trivy JSONs were never committed (large, git-ignored), so they were
regenerated **offline from the committed `juice-shop.cdx.json` SBOM** — `grype sbom:...` and `trivy sbom ...` —
without re-pulling the image (the image lived in the old Docker Desktop VM, not the Colima VM). Checkov and
Semgrep were regenerated via their official containers against `labs/lab6/vulnerable-iac/`.

**Format caveats found during import:**
- ZAP: the DefectDojo `ZAP Scan` parser requires the XML report, not JSON (`Wrong file format, please use xml`).
  The JSON `auth-report.json` also had zero alerts, so ZAP contributes 0 findings. The scan type is present in
  the engagement; the finding count is genuinely zero.
- Deduplication is **off by default** in a fresh DefectDojo. It was enabled via
  `PATCH /system_settings/ {"enable_deduplication": true}` before the cross-tool dedup below would register.

### Dedup example (cross-tool)
- **CVE/ID:** GHSA-5mrr-rgp6-x4gr (Command Injection in `marsdb` 0.6.11, Critical)
- **Number of source tools: 3** — Anchore Grype (test 1), Trivy-from-SBOM (test 2), Trivy image scan from Lab 7 (test 8)
- The same vulnerability imported a 4th time (test 12, the Trivy re-import) was auto-flagged
  `duplicate: true` and collapsed against the master finding.
- **DefectDojo master finding ID:** 106
- Engagement-wide, **80 findings** were flagged as duplicates once deduplication was enabled — almost the
  entire second Trivy import collapsed onto the Grype + first-Trivy set, since both scanned the same SBOM.

---

## Task 2: Governance Report

### Executive Summary
OWASP Juice Shop, scanned across six tools (Grype, Trivy, Semgrep, ZAP, Checkov, KICS) spanning SCA, SAST,
DAST and IaC, currently has **338 active findings — 15 Critical + 150 High**. Three findings were remediated
this period and one Critical (crypto-js) was formally risk-accepted with an expiry date. Because every report
was imported in a single session, the time-based metrics below are effectively instantaneous and are reported
with that methodological caveat rather than as a real steady-state program.

### Findings by severity (active, non-duplicate)
| Severity | Count |
|----------|------:|
| Critical | 15 |
| High | 150 |
| Medium | 153 |
| Low | 11 |
| Info | 9 |

### Findings by source tool
| Tool | Active | Mitigated | Risk Accepted | Duplicate (collapsed) |
|------|-------:|----------:|--------------:|----------------------:|
| Anchore Grype (SCA) | 105 | 2 | 1 | — |
| Trivy — SBOM (SCA) | 79 | 1 | — | — |
| Trivy — image, Lab 7 (SCA) | 50 | — | — | — |
| Trivy — re-import (dedup demo) | 0 | — | — | 80 |
| Checkov (IaC) | 80 | — | — | — |
| KICS — ansible (IaC) | 10 | — | — | — |
| KICS — pulumi (IaC) | 6 | — | — | — |
| Semgrep (SAST) | 8 | — | — | — |
| ZAP (DAST) | 0 | — | — | — |

### SLA matrix applied
Configured on the Default SLA configuration (id 1) and bound to the product:
| Severity | SLA |
|----------|-----|
| Critical | 24 hours (1 day) |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

### Program metrics
- **MTTD** (Mean Time to Detect): effectively 0 days — all findings were detected (imported) on 2026-07-10.
  In a real program this is (finding.date − commit/build date); here the capstone imports a whole semester at once.
- **MTTR** (Mean Time to Remediate): **< 1 day** across the 3 closed findings (detected and mitigated 2026-07-10).
  For reference, DORA "Elite" restore time is < 1 day, so this is not a meaningful benchmark given the setup.
- **Vuln-age median** (open findings): 0 days (oldest active finding dated 2026-07-10).
- **Backlog trend**: +338 active vs. a zero baseline — this is the first period, so the entire backlog is net-new.
- **SLA compliance**: 100% at time of writing — every finding was created today, so no Critical has yet crossed
  its 24-hour window; the clock is running, not breached. This will degrade automatically if the 15 Criticals
  are not addressed within 24h, which is exactly what the SLA matrix is there to surface.

### Risk-accepted items (all must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| #25 GHSA-xwcq-pm8m-c4vf in crypto-js 3.3.0 | Critical | Transitive dependency; no non-breaking upstream bump available yet. Accepted with review deadline. | 2026-10-10 |

Created as a proper `risk_acceptance` object (id 1, owner=admin, decision=`A`), not a loose flag — so the
expiry is enforced by DefectDojo and the finding will auto-reactivate when it lapses. This is the
"silent program killer" guard: a risk accepted without an expiry never comes back for review.

### Next-quarter goal (OWASP SAMM)
Mature **Defect Management → Metrics & Feedback** (SAMM Operations domain). Right now the SLA clock is real but
MTTR is meaningless because detection and closure collapse into one import day; the concrete next step is to wire
detection dates to CI build timestamps and ingest **Falco runtime alerts via a custom parser** so the runtime
layer (Lab 9) becomes a fourth finding source alongside SCA/SAST/IaC. Target: a genuine High-severity MTTR under
7 days measured across real commit-to-close intervals, instead of the instantaneous numbers this capstone produces.

---

## Bonus: Interview Walkthrough
- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: 4:45
- Two anticipated Q&A questions covered: yes
- Strongest claim in the script: "One Critical — marsdb command injection — was independently confirmed by three separate scanners and collapsed into a single tracked finding, which is the whole point of aggregation."
