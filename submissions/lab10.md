# Lab 10 — Vulnerability Management: The Capstone

DefectDojo 2.58.3 (pinned), six-container `release` stack via Docker Compose, running on a Colima VM.
Nine scanner reports from Labs 4 to 7 imported through the batch importer and the DefectDojo API v2.

## Task 1

### What imported, with parser and finding count

| Lab | File | Parser | Findings |
|---|---|---|---:|
| 4 | `grype-from-sbom.json` | Anchore Grype | 183 |
| 4 | `trivy.json` | Trivy Scan | 177 |
| 5 | `semgrep.json` | Semgrep JSON Report | 27 |
| 5 | `auth-report.xml` | ZAP Scan | 13 |
| 6 | `checkov-terraform/results_json.json` | Checkov Scan | 59 |
| 6 | `kics-ansible/results.json` | KICS Scan | 10 |
| 6 | `kics-pulumi/results.json` | KICS Scan | 6 |
| 7 | `trivy-image.json` | Trivy Scan | 87 |
| 7 | `trivy-k8s.json` | Trivy Operator Scan | 0 |

Two of these needed a decision rather than a straight run:

- **ZAP imported as XML, not JSON.** The lab's table maps `auth-report.json` to the `ZAP Scan` parser, but
  DefectDojo 2.58.3's ZAP parser rejects JSON: `Internal error: Wrong file format, please use xml`. Rather
  than re-run the 20-minute authenticated scan, I converted the Lab 5 `auth-report.json` to ZAP's XML
  schema (same 13 alerts, same fields) and imported that. The failed JSON attempt left an empty test, which
  I deleted so the dashboard shows one ZAP test of 13 findings.
- **`trivy-k8s.json` parsed to 0 findings.** The `Trivy Operator Scan` parser expects the Trivy Operator
  CRD report shape, and the Lab 7 output is from `trivy k8s` (a different JSON layout), so the import
  succeeds (HTTP 201) but yields nothing. The file imported; it just carried no findings the parser could
  read. This is worth knowing: a green import is not the same as findings landing.

### Active findings by severity

```console
$ curl ... "/api/v2/findings/?active=true&limit=2000" | jq '[.results[].severity] | group_by(.) | ...'
```

| Severity | Count |
|---|---:|
| Critical | 36 |
| High | 253 |
| Medium | 213 |
| Low | 47 |
| Info | 13 |
| **Total active** | **562** |

The total is the exact sum of the per-file counts above, which is itself a result: DefectDojo did **no
cross-tool deduplication** on import. 562 is a count of findings, not of distinct problems.

### Two duplicate titles: one issue twice, or two findings

- **`CVE-2015-9235 Jsonwebtoken 0.1.0`** appears twice, and it is **one issue counted twice**. It is in
  test 2 (`trivy.json`, Lab 4) and test 8 (`trivy-image.json`, Lab 7). Both are Trivy scanning the *same*
  Juice Shop image at two points in the course, so the same CVE on the same package version is recorded
  twice. I decided this by listing the titles in each test and intersecting them: **76 titles overlap**
  between the two Trivy scans. These are exactly the duplicates DefectDojo's deduplication would collapse
  if it were enabled on the engagement; here it was not, so they double-count.
- **`...express-sequelize-injection`** appears 6 times, and these are **six separate findings**. All six
  are from Semgrep (one tool), but each sits at a different `file:line`: `routes/search.ts:23`,
  `routes/login.ts:34`, and four `data/static/codefixes/*.ts` locations. I decided this by reading each
  finding's `file_path` and `line`: all distinct, so the rule genuinely fired at six code sites. Same
  title, six real instances.

The contrast is the point. A repeated title can mean the same defect recorded by two scans (collapse it)
or one rule matching many places (keep them). You cannot tell from the count; you have to read the
location.

### Which labs gave findings to act on, and which gave noise

The findings worth acting on this week came from **Lab 5 (Semgrep + ZAP)** and **Lab 4/7 (Grype + Trivy
on the image)**. Semgrep's `express-sequelize-injection` on `routes/search.ts:23` and ZAP's confirmed SQL
injection on `/rest/products/search` are the same real, unauthenticated, exploitable bug reached from two
directions, and the Trivy/Grype image CVEs include fixable criticals (`crypto-js`, `tar`, `jsonwebtoken`)
that are one dependency bump away. The **noise** is concentrated in **Lab 6 (Checkov + KICS)** and the
`codefixes` half of Semgrep: the 59 Checkov and 16 KICS findings are real, but they are against the
*deliberately vulnerable* `vulnerable-iac/` teaching fixtures and the Pulumi/Ansible samples, not against
anything this project ships, so they inflate the count without representing deployable risk. Four of the
six Semgrep SQL-injection hits are in `data/static/codefixes/`, which are intentionally broken challenge
snippets, not application code. The one number (562) hides this completely, which is why severity and
*source* both have to be on the governance report, not just the total.

## Task 2

### My SLA numbers against the defaults

| Severity | Default (days) | Mine (days) | Why |
|---|---:|---:|---|
| Critical | 7 | **3** | A reachable critical in an internet-facing app is likely exploitable now; many are KEV-listed. A week of exposure is too long, so three days forces either a fix or a documented risk acceptance fast. |
| High | 30 | **14** | A month lets a high sit unowned through a full sprint. Two weeks ties it to one sprint boundary, which is enough to schedule and ship a dependency bump. |
| Medium | 90 | **60** | A quarter is long enough that mediums are forgotten. Sixty days keeps them on the backlog as real work rather than a someday pile. |
| Low | 120 | **90** | 120 days is effectively never. Ninety days still deprioritises lows without pretending they do not exist. |

### Active findings by severity and by source tool

Severity: Critical 36, High 253, Medium 213, Low 47, Info 13 (total 562, as above).

| Source tool | Active findings |
|---|---:|
| Trivy Scan (Lab 4 + Lab 7 image) | 264 |
| Anchore Grype (Lab 4) | 183 |
| Checkov Scan (Lab 6) | 59 |
| Semgrep JSON Report (Lab 5) | 27 |
| KICS Scan (Lab 6 ansible + pulumi) | 16 |
| ZAP Scan (Lab 5) | 13 |

### Three numbers, with the method

Findings were backdated to their real scan dates (the Lab 4/5/6 reports to 2026-09-21, the Lab 7 image
scan to 2026-10-04) via `PATCH /api/v2/findings/{id}/` so the ages reflect the nine-week engagement rather
than the single import session. "Today" for the calculation is 2026-10-11.

- **Median age: 20 days.** From `jq` over `age` on all active findings: 475 are 20 days old (the
  September batch), 87 are 7 days old (the October image scan); sorted, the midpoint falls in the 20-day
  group.
- **Oldest active finding: 20 days.** `[.results[].age] | max` over active findings.
- **Within SLA: 349 of 562, 62.1%.** For each active finding I compared its `age` to my SLA for its
  severity (`critical=3, high=14, medium=60, low=90`): within-SLA if `age <= sla[severity]`. The 213
  breaches are **all 36 criticals** (any age beats a 3-day SLA) and **177 of the 253 highs** (the 20-day
  September highs breach the 14-day SLA; the 76 highs from the 7-day image scan are still inside it). Every
  medium and low is inside SLA. So the program is 38% out of SLA, and the entire breach is in the two
  severities that matter.

### What Labs 8 and 9 produced that none of these numbers include

**Nothing from Lab 8 (cosign signatures and SBOM/SLSA attestations) or Lab 9 (Falco runtime alerts and
Conftest policy results) is in the 562.** DefectDojo has no parser for a cosign attestation or a Falco
JSON alert, so the supply-chain signing posture and every runtime detection are invisible here. What I
would do: treat Lab 8's `cosign verify-attestation` as a *gate* in CI (a pass/fail that blocks a deploy,
not a finding to age), and route Falco alerts into DefectDojo through its Generic Findings Import or a
small custom parser so a cryptominer alert becomes a tracked, SLA'd finding instead of a line in a log
nobody reads. The dashboard currently measures scanning, not enforcement or runtime, and a manager reading
only these numbers would not know whether the image is even signed.

### A risk acceptance, with expiry and compensating control

**Finding: `GHSA-5mrr-rgp6-x4gr` in `marsdb 0.6.11` (Critical, no fix available).** marsdb is an
unmaintained transitive dependency with no patched release, so there is no version bump to make. I would
risk-accept it **until 2026-12-15** (the engagement end), with the compensating controls already built in
earlier labs: the Lab 7 deployment runs the container with `readOnlyRootFilesystem: true`, all
capabilities dropped and `allowPrivilegeEscalation: false`, and the Lab 9 NetworkPolicy default-denies
egress, so even if the marsdb code path were reached it has no writable filesystem and no outbound network
to exfiltrate through. The acceptance expires on a date, at which point it is re-reviewed rather than
renewed silently. The same treatment covers the other no-fix criticals (`decompress`), which are likewise
unreachable-and-contained rather than fixable.

### Executive summary

The Juice Shop project has 562 active findings across six scanners, but the real exposure is narrow: one
unauthenticated SQL injection (`/rest/products/search`) confirmed by both SAST and DAST, plus a handful of
fixable critical CVEs in the image, while most of the count is deliberately vulnerable IaC fixtures that
never ship. The single biggest risk is that SQL injection, because it is reachable without a login, proven
exploitable, and fixable in two lines with parameterised queries. To close it I need one developer-day to
land the `routes/search.ts` and `routes/login.ts` fix and re-run the ZAP authenticated scan to confirm,
and the dependency bumps for `crypto-js`, `tar` and `jsonwebtoken` scheduled into the next sprint against
the 14-day high SLA.

## Bonus note

The hardest part of the semester to explain concisely was the supply-chain chain of Lab 8: signing a
digest, attaching an SBOM as an attestation, and proving a swapped image fails verification is three
linked ideas that only make sense together, and none of them produces a number that lands on this
dashboard. Everything else reduces to "we found X issues of severity Y"; signing reduces to "trust this
artifact is the one we built," which a findings count cannot express. That tells me the next project needs
its story written per *control*, not per *tool* — a one-line statement of what each control guarantees and
how you would check it, captured when the control is built rather than reconstructed at the end, so the
parts that do not become a finding still have a place in the report.
