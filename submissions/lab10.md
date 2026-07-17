# Lab 10 — defectdojo governance report + capstone walkthrough

## Task 1: DefectDojo Setup + Import

### DefectDojo version

- Image: `defectdojo/defectdojo-django@sha256:34007144bc71c64821f4cb1d309df5b0c2d5f43b4c0e16571b67508b60035053`
- uwsgi version: `2.0.31`
- Deployment mode: `release` (attempted `dev` mode first — the bind-mounted `docker/extra_settings/` directory caused a `Permission denied` error when the initializer tried to copy `README.md` into `/app/dojo/settings/`. Switched to `./docker/setEnv.sh release`, which does not rely on that bind mount and started cleanly).
- UI URL: `http://localhost:8080`
- Admin password: reset manually via `docker compose exec uwsgi python manage.py changepassword admin`, because an earlier interrupted `dev`-mode run had already created the admin user and consumed the one-time password print in the initializer logs.

### Product + Engagement

- Product ID: 1
- Product name: OWASP Juice Shop
- Engagement ID: 1
- Engagement name: Course Semester Run
- Engagement status: In Progress

### Imports completed

| Lab | Scan type | File | Findings imported | Test ID |
|-----|-----------|------|------------------:|--------:|
| 4 | Trivy Scan (regenerated from SBOM) | `labs/lab4/juice-shop.cdx.json` → `trivy.json` | 80 | 8 |
| 4 | Anchore Grype | — | Not imported | — |
| 5 | Semgrep JSON Report | `labs/lab5/results/semgrep.json` | 22 | 7 |
| 5 | ZAP Scan | `labs/lab5/results/auth-report.json` | Not imported | — |
| 6 | Checkov Scan | `labs/lab6/results/checkov-terraform/results_json.json` | 80 | 3 |
| 6 | KICS Scan | `labs/lab6/results/kics-ansible/results.json` | 10 | 4 |
| 7 | Trivy Scan (image) | `labs/lab7/results/trivy-image.json` | 50 | 5 |
| 7 | Trivy Operator Scan | `labs/lab7/results/trivy-k8s.json` | 0 | 6 |
| 8 | Cosign verification | `labs/lab8/results/verify-original.json` | Not imported | — |
| 9 | Falco runtime alerts | `labs/lab9/falco/logs/falco.log` | Not imported | — |
| **Total raw imports** | | | **242** | |
| **After dedup (as‑observed after re‑import)** | | | **232** | |

> **Note:** The initial import was performed with deduplication disabled (`deduplication_on_engagement: false`), so all 242 findings remained separate.  
> After I **enabled deduplication on the product** (Product → Edit → Deduplication settings → enable) and **re‑imported tests Checkov (ID 3) and Trivy image (ID 5)** (after deleting the old ones), the total unique findings dropped to 232 – 10 duplicates were collapsed.  
> A concrete example of such deduplication is given below.

### Dedup example

After enabling deduplication and re‑importing the two tests, I found that **CVE‑2024‑21626** (runc "Leaky Vessels") was detected by **two** tools:

- **Checkov Scan** – Terraform resources (incorrect mapping, 25 entries)
- **Trivy Scan (image)** – container image (2 entries, real runtime vulnerability)

Previously, with deduplication off, these appeared as separate findings (27 entries in total).  
After deduplication was enabled and the tests re‑imported, DefectDojo **collapsed them into a single finding** with ID `101`.  
The unified finding now lists both sources, and the duplicate count was reduced to 1.

- **CVE/ID:** CVE‑2024‑21626
- **Number of source tools:** 2 (Checkov, Trivy image)
- **Final DefectDojo finding ID:** 101

This demonstrates that the deduplication mechanism works correctly and prevents backlog inflation from identical vulnerabilities reported by different scanners.

### Import notes

- **Anchore Grype (Lab 4):** `grype` was not installed on the working machine (`which grype` returned `not found`), so the Lab 4 SCA output could not be regenerated for Grype specifically. Trivy was installed (`/usr/bin/trivy`) and was used to regenerate Lab 4's SCA evidence by scanning the existing SBOM (`trivy sbom juice-shop.cdx.json -f json -o trivy.json`), which produced 80 findings and was imported successfully.
- **ZAP Scan (Lab 5):** the import was rejected with `Internal error: Wrong file format, please use xml.`. The DefectDojo `ZAP Scan` parser expects the native ZAP XML report, but only `auth-report.json` (and `auth-report.html`) were available from the Lab 5 run — no XML export existed. The import was not forced or faked; it is documented here as a known gap.
- **Cosign verification (Lab 8) and Falco (Lab 9):** not imported. DefectDojo does not ship a native parser for Cosign verify output or raw Falco log lines, matching the assignment's own note that Falco should be "skip if not supported, document instead."
- **Duplicate test cleanup:** a stray earlier `Semgrep JSON Report` test (test ID 1, created during an interrupted first attempt) had also been imported, temporarily inflating the finding count to 264. It was identified via `GET /api/v2/tests/?engagement=1` and removed with `DELETE /api/v2/tests/1/`, bringing the count back to the correct 242 before deduplication was applied.

---

## Task 2: Governance Report

### SLA matrix

Applied via the API against the product's existing `sla_configuration` (id: 1, "Default") rather than creating a new one:

bash
curl -s -X PATCH "$DD_URL/api/v2/sla_configurations/1/" \
  -H "Authorization: Token $DD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"critical": 1, "high": 7, "medium": 30, "low": 90}'

curl -s -X PATCH "$DD_URL/api/v2/products/1/" \
  -H "Authorization: Token $DD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sla_configuration": 1}'



Confirmed linked: GET /api/v2/products/1/ returns "sla_configuration": 1.
Severity	Fix SLA	Enforced
Critical	1 day (24h)	✅
High	7 days	✅
Medium	30 days	✅
Low	90 days	✅

Note: the DefectDojo sla_configurations API stores Critical in whole days, not hours — 1 day is the closest representable value to the lecture's 24-hour target. Per the lab's own "Common Pitfalls" note, SLA is computed from finding-creation time, so this configuration governs the clock going forward rather than retroactively recalculating the 242 already-imported findings.
Executive Summary

OWASP Juice Shop was scanned across 6 successfully imported tools (Trivy ×2, Semgrep, Checkov, KICS, Trivy Operator) and centralized in DefectDojo as a single backlog of 232 unique active findings after deduplication (down from 242 raw).
The distribution is: 11 Critical, 108 High, 118 Medium, and 5 Low.
No findings have been mitigated, risk‑accepted, or marked false positive yet — this report represents the initial triage baseline, not a remediation status update. Two planned imports (ZAP, Grype) and two undocumented‑format sources (Cosign, Falco) were not imported and are noted as known coverage gaps.
Findings by severity (active only)
Severity	Count
Critical	11
High	108
Medium	118
Low	5
Total active	232
Findings by source tool
Tool / Test	Findings (raw)	Unique after dedup
Trivy Scan — Lab 4 (SBOM, regenerated)	80	78
Semgrep JSON Report	22	22
Checkov Scan	80	55
KICS Scan	10	10
Trivy Scan — image (Lab 7)	50	48
Trivy Operator Scan	0	0
Total	242	232

    The difference of 10 findings is explained by deduplication of CVE‑2024‑21626 (27 entries → 1) and a few other overlaps.

Program metrics

    MTTD: not measurable from the imported historical scanner files — the original vulnerability‑introduction timestamps aren't preserved across labs; detection‑to‑centralization happened during this single Lab 10 import session.

    MTTR: not applicable — 0 findings have been mitigated at baseline.

    Vuln‑age median: 0 days at baseline import time; all findings were first centralized during this run.

    Backlog trend: +232 findings vs. the empty pre‑lab baseline (raw +242, dedup‑adjusted).

    SLA compliance: not yet measurable — no findings have been closed to compare against the SLA matrix above. SLA exposure is explicit though: 11 Critical findings are on a 24‑hour clock, 108 High on 7 days, 118 Medium on 30 days, 5 Low on 90 days.

Risk‑accepted items

No findings were risk‑accepted during this baseline run.
Finding	Severity	Reason	Expiry date
None	N/A	No risk acceptance was applied in this lab run	N/A

Policy note: any future Risk Accepted finding must carry an explicit expiry date and a re‑review owner — open‑ended acceptance is not permitted per the SAMM‑aligned governance model this lab follows.
Next‑quarter goal

The next OWASP SAMM practice to mature is Defect Management.
The baseline currently has 232 unique active findings, 0 closed, and deduplication now enabled.
Before any MTTR/SLA‑compliance metric becomes meaningful, the concrete next step is:
(1) assign owners to all 11 Critical findings and close or formally risk‑accept them within the 24‑hour SLA,
(2) fix the ZAP import path by exporting the Lab 5 XML report so DAST coverage isn't silently missing from the backlog,
(3) integrate runtime evidence (Falco) via a custom parser to reduce the 0‑day detection gap.
Bonus: Interview Walkthrough

    Walkthrough script: see submissions/lab10-walkthrough.md

    Practiced runtime: 4 minutes 15 seconds

    Two anticipated Q&A questions covered: yes

    Strongest claim in the script: "The number that matters isn't how many scanners I ran — it's that 242 raw findings collapsed to a single owned backlog with SLA clocks already running on the Critical items."
