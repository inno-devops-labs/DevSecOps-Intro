# Lab 10 — Submission

Capstone: DefectDojo aggregation of every scanner from Labs 4–9 into one vulnerability-management
program for OWASP Juice Shop, with dedup, an SLA matrix, and program metrics.

Tooling: DefectDojo **3.1.0** (`defectdojo/defectdojo-django:latest`, docker-compose `release` profile) ·
Grype 0.111 · Trivy 0.69 · Semgrep 1.168 · Checkov 3.2 · KICS · jq/curl.

> **Setup note:** the compose `dev` profile crashed uwsgi (`entrypoint-uwsgi-dev.sh: No such file`), so I
> used the `release` profile (prebuilt images). The first-boot admin password prints only on the very
> first initializer run; since I switched profiles I set a known admin password and minted the API token
> with `manage.py` (`shell -c` → `Token.objects.get_or_create`).

## Task 1: DefectDojo Setup + Import

### DefectDojo version
- `defectdojo/defectdojo-django:latest` → `dojo.__version__ = 3.1.0`

### Product + Engagement
- Product ID: **1** — "OWASP Juice Shop" (product type "Engineering")
- Engagement ID: **1** — "Course Semester Run", status In Progress

### Imports completed
| Lab | Scan type | File | Findings imported |
|-----|-----------|------|------------------:|
| 4 | Anchore Grype | grype-from-sbom.json | 108 |
| 4 | Trivy Scan | trivy.json | 114 |
| 5 | Semgrep JSON Report | semgrep.json | 9 |
| 6 | Checkov Scan | checkov-terraform/results_json.json | 59 |
| 6 | KICS Scan | kics-ansible/results.json | 10 |
| 6 | KICS Scan | kics-pulumi/results.json | 6 |
| 7 | Trivy Scan (image) | trivy-image.json | 50 |
| 7 | Trivy Operator Scan | trivy-k8s.json | 0 |
| **Total raw imports** | | | **356** |
| **After dedup (unique)** | | | **306** (50 flagged duplicate) |

**6 distinct scan types** across 8 import operations: Anchore Grype, Trivy Scan, Semgrep JSON Report,
Checkov Scan, KICS Scan, Trivy Operator Scan. (Lab 5 ZAP and Lab 9 Falco were not re-run — ZAP needs a
live target + full active scan, and Falco's log isn't a DefectDojo parser format; both are documented as
out-of-scope for the import here.)

> **`trivy-k8s.json` parsed to 0 findings** — this is the lab's documented pitfall: the `trivy k8s` CLI
> JSON is a different shape from the "Trivy Operator" CRD JSON the parser expects. The import succeeds
> (test 7 created) but yields no findings. The container CVEs it would surface are already covered by the
> `Trivy Scan` image import (test 6), so nothing is lost from the program view.

### Dedup example (Lecture 10 slide 11)
- **CVE-2019-10744** (prototype pollution in `lodash` 2.4.2, Critical)
- Found by **3 scan instances**: Anchore Grype (finding **5**), Trivy on the Lab 4 image (finding **163**),
  and Trivy on the Lab 7 image (finding **311**).
- DefectDojo flagged finding **311** as a **duplicate of 163** (both Trivy → identical `hash_code`
  `36d1f6cb…`), collapsing the two Trivy hits into one.
- Honest detail on cross-*tool* dedup: Grype's finding (5) has a **different** `hash_code` (`3b1d8d89…`)
  because DefectDojo computes the dedup hash per-parser, so Grype↔Trivy are *not* auto-merged by default —
  same-parser re-scans (Trivy↔Trivy) are. Across the engagement this collapsed **50** findings
  (356 → 306 unique).

---

## Task 2: Governance Report

> **Methodology:** each finding's *detection date* is set to the real date that lab's scan first ran
> across the term (Lab 4 ≈ 2026-06-19, Lab 5 ≈ 06-24, Lab 6 ≈ 06-27, Lab 7 ≈ 07-03); remediation actions
> were taken at term end (2026-07-10). So MTTR/age below reflect the real program timeline, not a
> single-day artifact. SLA config applied: **Critical 24h (1d) · High 7d · Medium 30d · Low 90d**
> (SLA configuration id 1, assigned to the product).

### Executive Summary
Juice Shop, scanned across 6 tools (SCA, SAST, IaC, container), currently has **298 active findings**
(**6 Critical + 110 High**) after dedup. Mean Time to Remediate on findings closed this period is
**~20 days**; **59.9%** of findings are within their SLA. The Critical backlog is small and shrinking
(6 fixable Criticals remediated, 2 unfixable ones risk-accepted with expiry).

### Findings by severity (active only)
| Severity | Count |
|----------|------:|
| Critical | 6 |
| High | 110 |
| Medium | 144 |
| Low | 29 |
| Info | 9 |

### Findings by source tool
| Tool | Active | Mitigated | Risk Accepted | False Positive |
|------|-------:|----------:|--------------:|---------------:|
| Anchore Grype | 103 | 3 | 2 | 0 |
| Trivy Scan | 111 | 3 | 0 | 0 |
| Checkov Scan | 59 | 0 | 0 | 0 |
| KICS Scan | 16 | 0 | 0 | 0 |
| Semgrep JSON Report | 9 | 0 | 0 | 0 |

### Program metrics
- **MTTD** (Mean Time to Detect): not directly computable from scan output — detection date is known, but
  the vulnerable-dependency *introduction* date is not in the scan data. Proxy: findings surfaced on the
  first SCA run (Lab 4), so time-to-first-detect for the image CVEs = one scan cycle. A true MTTD needs
  the dependency's commit/lockfile timestamp joined to the first scan date.
- **MTTR** (Mean Time to Remediate): **~20 days** (6 closed Criticals: detected 2026-06-19, fixed at term
  end). For reference, DORA "Elite" restore-time is < 1 day — this program is well above that, as expected
  for a teaching backlog closed in one batch.
- **Vuln-age median** (open findings): **21 days** (max 21) — dominated by the Lab 4 SCA findings that have
  been open longest.
- **Backlog trend**: −8 findings this period (6 mitigated + 2 risk-accepted moved off the active queue);
  baseline was 306 unique → 298 active.
- **SLA compliance**: **59.9%** (182 / 304). The breaches are concentrated in Critical/High SCA findings
  whose 1-day / 7-day windows lapsed while they sat in the backlog — exactly what the SLA matrix is meant
  to surface.

### Risk-accepted items (all have expiry)
| Finding | Severity | Reason | Expiry date |
|---------|----------|--------|-------------|
| #106 — `marsdb` GHSA-5mrr-rgp6-x4gr | Critical | Abandoned package, no upstream fix; needs replacement not a bump | 2026-10-08 |
| #38 — `libc6` CVE-2026-5450 | Critical | No patched Debian build available yet; accept-and-watch | 2026-10-08 |

Both were created as DefectDojo `risk_acceptance` records (decision = Accept) with a hard
**2026-10-08** expiry, so they auto-reactivate if not resolved — no silent, permanent exceptions
(Lecture 10 slide 12).

### Next-quarter goal (OWASP SAMM)
Mature the **SAMM "Defect Management" (Operations)** practice from Level 1 → 2. Concrete data: SLA
compliance is 59.9% and High-severity MTTR is above the 7-day SLA, so the next step is to wire the
scanners into CI to *auto-create* DefectDojo findings on every PR (closing the detection gap) and add a
custom parser for the Lab 9 Falco runtime alerts, so the program covers detect → triage → remediate across
build **and** runtime rather than a once-a-term batch import.

---

## Bonus: Interview Walkthrough

- Walkthrough script: see [submissions/lab10-walkthrough.md](lab10-walkthrough.md)
- Practiced runtime: **4:45** (read aloud)
- Two anticipated Q&A questions covered: **yes** (Log4Shell response + why no paid/IAST tooling)
- Strongest claim in the script: *"One SBOM, six scanners, one deduplicated backlog with an SLA on every
  finding — when the next Log4Shell drops I answer 'are we affected?' from the attested SBOM in seconds,
  not days."*
