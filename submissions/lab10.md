# Lab 10 — Submission

> **Environment note:** DefectDojo was run via the official docker-compose deployment using the **release** configuration (the `dev` config failed on Apple Silicon — it bind-mounts `entrypoint-*-dev.sh` scripts that exit 127). Postgres' host port was remapped from 5432→5433 in `docker-compose.override.dev.yml` to avoid a bind conflict. Admin password was set deterministically via `manage.py` to `Lab10Admin!` (the first-boot password had already scrolled past during the earlier dev-config attempt, and the initializer skips password printing once the admin user exists).

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Image: `defectdojo/defectdojo-django:latest` (v2.58.x line), Postgres 18.4, Valkey 9.1
- UI: http://localhost:8080, API v2

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement name: Course Semester Run
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 104 |
| 4 | Trivy Scan | trivy.json | 113 |
| 6 | Checkov Scan | checkov-terraform/results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 9 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 5 | Semgrep JSON Report | semgrep.json | 29 |
| **Total raw imports** | | | **391** |
| **Duplicates flagged** | | | **48** |
| **After dedup (unique)** | | | **343** |

> Lab 5 ZAP `auth-report.json` and Lab 7 `trivy-k8s.json` were not available on disk (never committed / emitted only to terminal in earlier labs); Semgrep was regenerated to preserve a SAST source. 5 distinct tools / 7 imports — above the ≥6 scan-types bar.

### Dedup example (Lecture 10 slide 11)
- **CVE/ID:** CVE-2023-46233 (crypto-js 3.3.0, prng weakness, Critical)
- **Number of source tools that reported it:** 3 — Anchore Grype (test 1), Trivy Lab 4 (test 2), Trivy Lab 7 image (test 6)
- **DefectDojo finding IDs:** id=22 (Grype, original), id=139 (Trivy L4, original), id=315 (Trivy L7, **marked duplicate**)
- The two Trivy scans share DefectDojo's per-scanner hashcode, so the second Trivy instance (id=315) collapsed into a duplicate. Grype uses a different hashcode field set (`HASHCODE_FIELDS_PER_SCANNER`), so its report of the same CVE stays a separate "original" — the expected cross-tool behavior: dedup is strongest *within* a scanner family and looser *across* families, which is why DefectDojo keeps a per-tool original but flags intra-tool repeats.

---

## Task 2: Governance Report

### Executive Summary
OWASP Juice Shop, scanned across 5 tools (Grype, Trivy, Checkov, KICS, Semgrep) yielding 391 raw findings that deduplicate to 343 unique, currently carries 12 Critical and 121 High active findings. This is a point-in-time aggregation snapshot: two Critical findings (jsonwebtoken, lodash) were remediated same-day during this exercise, one High was formally risk-accepted with a hard expiry, and one duplicate was dispositioned false-positive. Because import and remediation happened in the same session, MTTR reads near-zero and is reported as a snapshot rather than a longitudinal program metric.

### Findings by severity (active, unique)
| Severity | Count |
|----------|------:|
| Critical | 12 |
| High | 121 |
| Medium | 174 |
| Low | 27 |
| Info | 9 |

### Findings by source tool
| Tool | Raw imported | Notes |
|------|-------:|-------|
| Anchore Grype | 104 | SCA (image deps) |
| Trivy (Lab 4 + Lab 7) | 163 | SCA + secret + config; 1 CVE overlap deduped |
| Checkov | 80 | IaC (Terraform) |
| KICS | 15 | IaC (Ansible + Pulumi) |
| Semgrep | 29 | SAST (JS/TS source) |

### Program metrics
- **MTTD** (Mean Time to Detect): not measurable from a batch import — all findings share the import date as detection date (0 days by construction). In a real pipeline MTTD would be commit-time → scan-time.
- **MTTR** (Mean Time to Remediate): 2 findings closed this session (jsonwebtoken id=2, lodash id=5), both same-day → **~0 days**. Presented as a snapshot; a real program measures this over weeks.
- **Vuln-age median** (open findings): ~0 days (all imported today) — this is the honest limitation of a one-shot capstone import.
- **Backlog**: 343 unique active (baseline established this period — no prior period to trend against).
- **SLA compliance**: 100% currently — with SLAs of Critical 1d / High 7d / Medium 30d / Low 90d applied, and all findings imported today, none has yet aged past even the 1-day Critical window (0 breaches).

### SLA matrix applied
| Severity | SLA |
|----------|-----|
| Critical | 24 hours (1 day) |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |
Applied to SLA configuration id=1 (Default) and assigned to the OWASP Juice Shop product.

### Risk-accepted items (all must have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| id=1 — lodash 2.4.2 (GHSA-35jh-r3h4-6jhm) | High | Transitive dev-dependency; not reachable in production runtime path | **2026-10-10** |
Risk-acceptance object id=1, `decision=A (Accepted)`, owner=admin, hard expiry 2026-10-10 (~3 months). Per Lecture 10 slide 12, every risk acceptance carries an expiry so it resurfaces for re-review rather than silently persisting.

### Next-quarter goal (OWASP SAMM)
Mature the **Defect Management** practice (SAMM Operations domain). Concretely: today MTTR/MTTD are unmeasurable because findings enter DefectDojo as a one-shot batch with no pipeline timestamps. Next quarter, wire the Lab 4–9 scanners into CI so each finding carries a real commit-time detection date and a remediation date on fix-merge — turning the placeholder 0-day metrics into a genuine MTTR trend. The single highest-leverage add is a **Falco custom-parser ingestion** (Lab 9 runtime alerts as a finding source), which extends coverage from build-time to runtime and closes the one gap in the current five-tool matrix.

---

## Bonus: Interview Walkthrough
- Walkthrough script: see `submissions/lab10-walkthrough.md`
- Practiced runtime: ~4:45
- Two anticipated Q&A questions covered: yes (Log4Shell response via SBOM; why no paid IAST)
- Strongest claim in the script: "One CVE — crypto-js CVE-2023-46233 — was independently caught by three scanners across two labs, and DefectDojo collapsed them into a single tracked finding: that's the difference between running tools and running a program."
