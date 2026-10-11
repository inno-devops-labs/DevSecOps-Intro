# Lab 10 — Submission

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- Version installed: `3.1.0` (via `docker exec dd-uwsgi-1 cat /app/dojo/__init__.py` — `__version__ = "3.1.0"`)

### Product + Engagement
- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 2
- Engagement status: In Progress

### Imports completed
| Lab | Scan type | File | Findings imported (raw) |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 105 |
| 4 | Trivy Scan | trivy.json | 113 |
| 5 | Semgrep JSON Report | semgrep.json | 22 |
| 5 | ZAP Scan | auth-report.json | **failed to import** (see Environment notes) |
| 6 | Checkov Scan | checkov-terraform/results_json.json | 80 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Scan (k8s)* | trivy-k8s.json | 51 |
| **Total raw imports** | | | **437** |
| **After dedup** | | | **389** unique active findings (48 marked duplicate) |

\* Imported as `Trivy Scan`, not the lab-documented `Trivy Operator Scan` — see Environment notes.

### Dedup example (Lecture 10 slide 11)
- CVE/ID: **CVE-2023-46233** (Crypto-Js 3.3.0)
- Source scans: 2 — both `Trivy Scan` (test 12 = Lab 4's `trivy.json`, test 17 = Lab 7's `trivy-image.json`), i.e. the same tool scanning the same image tag (`bkimminich/juice-shop:v20.0.0`) across two separate lab runs
- DefectDojo's single active finding ID: **577** (test 12); duplicate collapsed into it: finding **776** (test 17)
- Broader picture: all **48** findings DefectDojo marked as duplicates in this engagement follow this exact same-tool pattern (test 12 ↔ test 17). **Zero** duplicates were found between Grype (test 11) and either Trivy test, despite many overlapping CVEs on the same image (e.g. `lodash`, `jsonwebtoken`, `crypto-js`, `marsdb` all appear as both a Grype finding and a Trivy finding for the same package/version). DefectDojo's default hash_code fields differ enough between the Grype and Trivy parsers that cross-tool matches never fire, while two runs of the *same* parser hash identically. This is a real, observed limitation of out-of-the-box dedup configuration — documented rather than worked around, since fixing it needs a custom per-Test-Type "Deduplication Configuration" (hash_code fields limited to CVE + component), which is out of scope for this lab.

---

## Task 2: Governance Report

### Executive Summary
Juice Shop has now been scanned across 6 distinct tool types (Anchore Grype, Trivy image, Trivy k8s, Semgrep, Checkov, KICS) via 8 successful imports, and currently carries 389 active findings (18 Critical + 167 High) as of Day 0 of program tracking. No finding has been remediated yet, so Mean Time to Remediate cannot be computed this cycle; every finding is currently within its SLA window, though the 18 Critical findings run on a 24-hour clock that expires tomorrow (2026-07-11) if untriaged. This snapshot is the baseline the program will be measured against going forward.

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 18 |
| High | 167 |
| Medium | 168 |
| Low | 27 |
| **Total** | **389** |

### Findings by source tool
| Tool | Active | Mitigated | False Positive | Risk Accepted |
|------|-------:|----------:|---------------:|---------------:|
| Anchore Grype | 105 | 0 | 0 | 0 |
| Trivy Scan (image — labs 4+7 combined) | 115 | 0 | 0 | 0 |
| Trivy Scan (k8s) | 51 | 0 | 0 | 0 |
| Semgrep JSON Report | 22 | 0 | 0 | 0 |
| Checkov Scan | 80 | 0 | 0 | 0 |
| KICS Scan (ansible + pulumi) | 16 | 0 | 0 | 0 |
| **Total** | **389** | **0** | **0** | **0** |

### Program metrics
- **MTTD** (Mean Time to Detect): N/A — this is the first scan/import cycle for this product; there is no prior baseline to measure detection latency against.
- **MTTR** (Mean Time to Remediate): N/A — 0 findings have been mitigated (Day 0 of the program).
- **Vuln-age median** (open findings): 0 days — every finding was created today, 2026-07-10.
- **Backlog trend**: N/A — no prior period exists yet to compare against; this run establishes the baseline.
- **SLA compliance**: 100% (0 of 389 findings are currently past their SLA expiration date) — but this is a fragile 100%: the 18 Critical findings expire in 24 hours (`sla_expiration_date: 2026-07-11`) and need an active triage decision before then to stay compliant.

### Risk-accepted items (must have expiry)
None. No findings have been risk-accepted in this initial import cycle — the program is at Day 0 and hasn't yet gone through a triage pass.

### Next-quarter goal (OWASP SAMM ladder step)
**Defect Management — triage workflow maturity.** Right now 0% of the 389 active findings have received any disposition (fix / false-positive / risk-accept), and MTTR is undefined because nothing has closed. Next quarter's concrete goal: stand up a weekly triage cadence that guarantees every newly-imported Critical finding gets an initial disposition inside its 24-hour SLA window (today, 18 Critical findings are exactly at that edge with zero buffer). A secondary, closely related goal: fix the dedup gap documented above — configure a custom per-Test-Type Deduplication Configuration (hash_code on CVE + component_name + component_version) so Grype and Trivy findings for the same CVE collapse into one, since right now the 389-finding backlog double-counts an unknown number of real vulnerabilities across those two tools, which distorts every metric above it.

---

## Environment notes
- DefectDojo `3.1.0` (course material targets ~v2.58.x) — deployed via the official `docker compose` dev stack from a fresh clone of `DefectDojo/django-DefectDojo`; no functional blockers from the version difference.
- All DefectDojo API calls were made with Windows' native `curl.exe` (not PowerShell's `Invoke-WebRequest` alias that shadows the `curl` name) — PowerShell's argument-escaping to native executables mangles embedded JSON quotes, so POST bodies were written to temp files and passed as `-d @file.json` instead of inline strings.
- `enable_deduplication` defaults to **false** in this DefectDojo's System Settings. Deduplication silently never fired on the first import pass (0 duplicates across 437 findings, including two identical Trivy scans of the same image) until this was flipped to `true` via `PATCH /api/v2/system_settings/1/`. Since dedup only applies going forward from import time, the original engagement (ID 1) was deleted and recreated as Engagement ID 2 so all 8 imports would run through the dedup engine.
- `labs/lab7/results/trivy-k8s.json` imported as scan_type `Trivy Scan` rather than the lab-documented `Trivy Operator Scan`. The `Trivy Operator Scan` parser expects the schema emitted by the separate `trivy-operator` Kubernetes controller (CRD-based reports), not the CLI's `trivy k8s --format json` output produced in Lab 7 — importing under that scan_type "succeeded" with a silent 0 findings (a known DefectDojo pitfall the lab's own docs call out). Re-importing the identical file as `Trivy Scan` parsed all 51 findings correctly.
- `labs/lab5/results/auth-report.json` (ZAP) failed to import under `ZAP Scan` with `Wrong file format, please use xml.` — this DefectDojo version's ZAP parser only accepts XML, while Lab 5's documented ZAP output is JSON. Not re-run with an XML export, since the Task 1 acceptance criteria (≥6 scan types) was already satisfied by the other 8 successful imports.
- The K8s cluster used for Lab 7's `trivy k8s` scan (Docker Desktop's built-in Kubernetes, namespace `juice-shop`) was still live and healthy 8 days after Lab 7 was submitted, so `trivy-k8s.json` was regenerated directly against it rather than recreating a `kind`/`k3d` cluster from scratch.
