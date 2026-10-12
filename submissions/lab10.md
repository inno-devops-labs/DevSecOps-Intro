# Lab 10 — Vulnerability Management: The Capstone

DefectDojo **2.58.3** (6-container `release` stack), published on host port **8081** because 8080 was already taken on this machine. Product `OWASP Juice Shop`, product type `Research and Development` (stock id 1, which the importer defaults to), engagement `Course Semester Run`. All numbers below come from the DefectDojo API (`/api/v2/findings/`, `/tests/`, `/sla_configurations/`).

## Task 1

### Parsers and finding counts per imported file

| Lab | File | Parser (scan_type) | Test | Findings |
|---|---|---|---|---|
| 4 | `grype-from-sbom.json` | Anchore Grype | 1 | 183 |
| 4 | `trivy.json` | Trivy Scan | 2 | 177 |
| 5 | `semgrep.json` | Semgrep JSON Report | 3 | 27 |
| 5/10 | `zap-baseline.xml` | ZAP Scan | 10 | 10 |
| 6 | `checkov-terraform/results_json.json` | Checkov Scan | 5 | 80 |
| 6 | `kics-ansible/results.json` | KICS Scan | 6 | 10 |
| 6 | `kics-pulumi/results.json` | KICS Scan | 7 | 6 |
| 7 | `trivy-image.json` | Trivy Scan | 8 | 87 |
| 7 | `trivy-k8s.json` | Trivy Operator Scan | 9 | 0 |

All nine reports imported. One honest note on ZAP: Lab 5's `auth-report.json` is ZAP's *JSON* report, but DefectDojo's `ZAP Scan` parser only accepts ZAP's *XML* export (`Internal error: Wrong file format, please use xml.`). I regenerated the ZAP report in XML (`zap-baseline.py -x`) against the same Juice Shop v20.0.0 and imported that; the empty JSON-import test shell was deleted so the dashboard shows a single ZAP test. The `Trivy Operator Scan` of the hardened k8s namespace produced **0** findings — correct, because that scan found no HIGH/CRITICAL workload issues, not because the import failed.

### Active findings by severity

| Severity | Count |
|---|---|
| Critical | 36 |
| High | 251 |
| Medium | 232 |
| Low | 49 |
| Info | 12 |
| **Total active** | **580** |

### Two titles that appear more than once

1. **`CVE-2015-9235 Jsonwebtoken 0.1.0`** appears in both test 2 (Lab 4 Trivy, full image) and test 8 (Lab 7 Trivy image, HIGH/CRITICAL) — **one issue counted twice**. It is the *same* CVE in the *same* package version of the *same* image, seen by the same scanner at two points in the course. 76 titles are shared between those two Trivy tests for exactly this reason. I decided it was a duplicate because the CVE id, package and version are identical and both point at the same image digest; deduplication is turned off on this instance, so DefectDojo lists them separately rather than collapsing them.
2. **`javascript.sequelize.security.audit...express-sequelize-injection`** (Semgrep) appears 6 times — **six separate findings**. The rule id is the title, but each hit is a different `file:line` (`routes/search.ts:23`, `routes/login.ts:34`, and four teaching snippets under `data/static/codefixes/`). I decided these are distinct because the location differs on every one; they share a rule name, not an underlying defect.

### Which of the nine labs gave findings I'd act on this week, and which gave noise

The findings worth acting on this week come from **Labs 4 and 7 (Trivy/Grype image scans)** and **Lab 5 (Semgrep + ZAP)**: the image carries Critical dependency CVEs with *released fixes* — `jsonwebtoken`, `lodash`, `crypto-js`, `tar` — that are a version bump away, and Semgrep's SQL-injection finding in `routes/login.ts` is a real, reachable auth-bypass. Those map to shippable tickets. The **noise** is mostly **Lab 6 (Checkov + KICS = 96 findings)**: those scan the deliberately broken `vulnerable-iac/` teaching fixtures, which are never deployed anywhere, so their count inflates the total without representing production risk. The Grype/Trivy overlap also double-counts the same image (76 shared CVEs), so the single "580" is larger than the number of distinct, actionable problems — which is the whole point of putting it in one system and triaging rather than reporting the raw total.

## Task 2

### SLA numbers vs the defaults

| Severity | Default (days) | Mine (days) | Why mine differ |
|---|---|---|---|
| Critical | 7 | **3** | A critical with a public exploit (CISA KEV / high EPSS) cannot sit exposed for a week; 3 days forces same-sprint action. |
| High | 30 | **14** | 30 days is a month of live exposure; 14 aligns the deadline to one two-week sprint so it is actually planned, not deferred. |
| Medium | 90 | **60** | 90 days quietly becomes "next quarter"; 60 keeps it inside the quarter with margin to batch fixes. |
| Low | 120 | **180** | Lows rarely justify displacing higher work, so 120 is a deadline we routinely miss; 180 is an honest commitment we can actually meet rather than a number we breach on paper. |

### Active findings by severity and by source tool

By severity: Critical 36 / High 251 / Medium 232 / Low 49 / Info 12 (total 580). By tool:

| Tool (lab) | Findings | Severity shape |
|---|---|---|
| Anchore Grype (4) | 183 | Crit 14, High 85, Med 65, Low 12, Info 7 |
| Trivy image (4) | 177 | Crit 10, High 66, Med 70, Low 31 |
| Trivy image (7) | 87 | Crit 11, High 76 |
| Checkov Terraform (6) | 80 | Med 80 |
| Semgrep (5) | 27 | High 13, Med 14 |
| KICS Ansible (6) | 10 | High 9, Low 1 |
| ZAP baseline (5/10) | 10 | Med/Low/Info header & CSP alerts |
| KICS Pulumi (6) | 6 | Crit 1, High 2, Med 1, Info 2 |
| Trivy Operator k8s (7) | 0 | — |

### Three numbers, with method

- **Median age of active findings: 1 day.** Method: `GET /findings/?active=true&limit=2000`, collected `.age` for all 580, sorted, took the middle value with `jq`.
- **Oldest active finding: 1 day.** Same array, `max`. Everything was imported on 2026-10-12, so age reflects *import* date, not original discovery — a real program would import continuously and this number would spread out.
- **Share currently inside SLA: 100%** (568 of 568 SLA-bearing findings; `sla_days_remaining >= 0` for every one). Method: collected `.sla_days_remaining`; the 12 Info findings have no SLA tier (null) and are not SLA-tracked, so they are excluded from the denominator rather than counted as breaches.

### What Labs 8 and 9 produced that none of these numbers include

Lab 8 produced Cosign **signatures and SBOM/SLSA attestations**, and Lab 9 produced **Falco runtime alerts and Conftest policy results** — DefectDojo has no parser for any of them, so supply-chain integrity and runtime/admission detection are entirely absent from the 580. I would track them as separate controls: gate the pipeline on `cosign verify-attestation` in CI (pass/fail, not a finding count), and ship Falco alerts to a SIEM (or import them via a generic-findings feed) so runtime detections become visible next to the scanner findings instead of living only in container logs.

### A finding I would risk-accept

The **Lab 6 IaC findings on `vulnerable-iac/`** (Checkov + KICS, 96 findings): risk-accepted until **2026-12-15** (course end), compensating control = **these manifests are teaching fixtures and are present in no deployment pipeline or cluster**, so they cannot reach production. The acceptance has an owner and an expiry; at 2026-12-15 it is re-reviewed rather than silently extended. ("We will not fix this" with no date would not be a decision.)

### Executive summary (three sentences)

The Juice Shop project now has every scanner from nine weeks in one DefectDojo instance — 580 active findings across SCA, SAST, DAST, IaC and container scans, all currently within freshly tightened SLAs. The single biggest risk is the set of **Critical dependency CVEs in the running image that already have fixes** (`jsonwebtoken`, `lodash`, `crypto-js`, `tar`) plus the confirmed SQL-injection in `routes/login.ts`, because they are both exploitable and cheap to close. To close it I need one maintainer-day to bump the vulnerable dependencies and rebuild the image, and a decision to exclude the deliberately-vulnerable IaC fixtures from the metric so the dashboard reflects production risk rather than teaching noise.

## Bonus reflection

The hardest part of the semester to explain concisely was **why the one big number (580) is not the risk** — that half of it is the same image counted twice by two scanners and a block of deliberately-broken teaching IaC, and that the real story is a handful of fixable Critical CVEs plus one SQL injection. Making a manager understand "the total went up and that is fine, here are the five things that matter" took far longer than running any tool. That tells me the next project needs its triage story documented *alongside* the raw output from day one — every scan import paired with a one-line "what here is actionable vs. noise" — so the narrative is not reconstructed at the end but accumulated as the evidence arrives. The full five-minute version is in `submissions/lab10-walkthrough.md`.
