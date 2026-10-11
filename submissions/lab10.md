# Lab 10 — Submission

> Ran DefectDojo **3.1.0** locally (docker-compose, 8 services) after raising the WSL2 memory to
> 10 GB via `.wslconfig`. Two environment notes: (1) `docker/setEnv.sh` uses symlinks, which don't
> work in Git-Bash on Windows — I ran in **release mode** (removed the stale dev override) so uwsgi
> used the baked entrypoint; (2) Docker Desktop's Windows→WSL2 port-forward for `:8080` was dead, so
> all API calls were made **from inside the `dd_default` network** (a `curlimages/curl` container
> hitting `http://nginx:8080`). The instance itself is fully functional.

## Task 1: DefectDojo Setup + Import

### Version + access
- DefectDojo version: **3.1.0**
- Admin: `admin` / `DojoAdmin1234!` (set via `manage.py`), API token generated for imports.

### Product + Engagement
- Product ID **1** — "OWASP Juice Shop" (prod_type: Research and Development)
- Engagement ID **1** — "Course Semester Run", type CI/CD, status In Progress

### Imports completed (8 imports across 6 scan types)
| Lab | Scan type | File | Findings |
|-----|-----------|------|---------:|
| 4 | Anchore Grype | grype-from-sbom.json | 105 |
| 4 | Trivy Scan | trivy.json | 113 |
| 5 | Semgrep JSON Report | labs/lab5/results/semgrep.json | 22 |
| 5 | ZAP Scan | labs/lab5/results/zap-report.xml | 9 |
| 6 | Checkov Scan | labs/lab6/results/checkov-terraform/results_json.json | 80 |
| 6 | KICS Scan | labs/lab6/results/kics-ansible/results.json | 10 |
| 6 | KICS Scan | labs/lab6/results/kics-pulumi/results.json | 6 |
| 7 | Trivy Scan | labs/lab7/results/trivy-image.json | 50 |
| **Raw total** | | | **395** |
| **After dedup** | | | **347 unique** (48 duplicates) |

> ZAP gotcha: DefectDojo's "ZAP Scan" parser rejects the `traditional-json` report
> (`Internal error: Wrong file format, please use xml.`). I regenerated the ZAP baseline with
> `-x zap-report.xml` and imported the XML.

### Dedup example (deduplication enabled, `manage.py dedupe` run over all 395)
- **CVE-2019-10744 — Lodash 2.4.2 (Critical).** Finding **#159** (Trivy, Lab 4 `trivy.json`) is the
  primary; finding **#350** (Trivy, Lab 7 `trivy-image.json`) was marked **duplicate** against it.
  In total **48 of the 50** Lab-7 Trivy-image findings collapsed into the Lab-4 Trivy scan — the
  cross-scan overlap you'd expect from scanning the same image twice.
- **Cross-*tool* nuance:** Grype reports the *same* Lodash vuln as `GHSA-jf85-cpcp-j695` (finding #5),
  which did **not** dedup against Trivy's `CVE-2019-10744` — the GHSA-vs-CVE identifier mismatch first
  seen in Lab 4 resurfaces at the dedup layer, because the two parsers hash different IDs. Aligning
  that is exactly the kind of hashcode-config tuning a real DefectDojo program does.

---

## Task 2: Governance Report

### SLA matrix (applied to `sla_configurations/1`)
**Critical 24h (1d) · High 7d · Medium 30d · Low 90d.**

### Executive summary
OWASP Juice Shop, scanned across **6 tools**, has **346 active unique findings** (12 Critical +
122 High) after dedup collapsed 395 raw imports to 347. This is the **program baseline** — the first
consolidated import — so nothing has been remediated yet: MTTR is not-yet-defined and SLA compliance
is 100% only because every finding is on day 0 of its window. The value delivered today is the
*single source of truth*: one product, one engagement, cross-tool dedup, and an SLA clock now running.

### Findings by severity (active, non-duplicate)
| Severity | Count |
|----------|------:|
| Critical | 12 |
| High | 122 |
| Medium | 170 |
| Low | 31 |
| Info | 11 |
| **Total active** | **346** |

### Findings by source tool (active / duplicate)
| Tool (scan) | Active | Duplicate |
|-------------|-------:|----------:|
| Anchore Grype (Lab 4) | 105 | 0 |
| Trivy — image (Lab 4) | 113 | 0 |
| Trivy — image (Lab 7) | 2 | 48 |
| Semgrep (Lab 5) | 22 | 0 |
| ZAP baseline (Lab 5) | 9 | 0 |
| Checkov — Terraform (Lab 6) | 80 | 0 |
| KICS — Ansible (Lab 6) | 10 | 0 |
| KICS — Pulumi (Lab 6) | 6 | 0 |

### Program metrics (baseline snapshot)
- **MTTD:** ~0 d — findings enter the program at scan time (CI-integrated).
- **MTTR:** n/a — 0 findings closed in this first period (baseline established today).
- **Vuln-age median:** ~0 d — all findings imported today; the clock now runs.
- **Backlog:** 346 active (baseline); target = falling once remediation starts.
- **SLA compliance:** 100% — nothing breached yet (day 0). The 12 Criticals hit their 24h SLA first;
  they're the top of the queue.

### Risk-accepted items (each has an explicit expiry)
| Finding | Severity | Reason | Expiry |
|---------|----------|--------|--------|
| #62 `GHSA-pxg6-pf52-xh8x` in cookie 0.4.2 | Low | Low severity; the cookie parser isn't internet-reachable in the lab deploy. Revisit at term end. | **2026-12-15** |

(Created as a DefectDojo `risk_acceptance` object with `expiration_date` — so it auto-expires and
re-activates the finding rather than silently rotting in the backlog.)

### Next-quarter goal (OWASP SAMM)
Mature **Defect Management**. The immediate lever is the **12 Criticals on a 24h SLA** — drive their
MTTR from *undefined* to *< 1 day* by wiring the top fixable ones (the `jsonwebtoken` / `lodash` /
`crypto-js` dependency bumps from Lab 4) into a remediation sprint. In parallel, add a **Falco
custom-parser** so runtime alerts (Lab 9) become first-class findings under the same SLA clock —
closing the loop between build-time CVEs and runtime detection in one system of record.

---

## Bonus: Interview Walkthrough
- Script: [`submissions/lab10-walkthrough.md`](lab10-walkthrough.md) — complete, 6 timed sections + 2
  anticipated Q&A.
- Strongest claim: *"The SBOM turns 'are we affected?' from a week of archaeology into a query."*
