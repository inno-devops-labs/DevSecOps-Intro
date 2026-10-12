# Lab 10 — Vulnerability Management: The Capstone

DefectDojo **2.58.3** (pinned clone, `release` profile, six containers: nginx, uwsgi, celerybeat, celeryworker, postgres, valkey). Peak memory across the stack was about 700 MB, comfortably inside the 4 GB the setup asks for.

Product `OWASP Juice Shop` (id 1, type `Research and Development`), engagement `Course Semester Run` (id 1, CI/CD, 2026-09-01 → 2026-12-15).

## Task 1

### What was imported, with parser and count

| Lab | File | Parser | Test | Active findings |
|---|---|---|---:|---:|
| 4 | `grype-from-sbom.json` | `Anchore Grype` | 1 | 230 |
| 4 | `trivy.json` | `Trivy Scan` | 2 | 225 |
| 5 | `semgrep.json` | `Semgrep JSON Report` | 3 | 27 |
| 5 | `auth-report.xml` | `ZAP Scan` | 10 | 8 |
| 6 | `checkov-terraform/results_json.json` | `Checkov Scan` | 5 | 80 |
| 6 | `kics-ansible/results.json` | `KICS Scan` | 6 | 10 |
| 6 | `kics-pulumi/results.json` | `KICS Scan` | 7 | 6 |
| 7 | `trivy-image.json` | `Trivy Scan` | 8 | 87 |
| 7 | `trivy-k8s.json` | `Trivy Operator Scan` | 9 | 0 |
| | | | **Total** | **673** |

All nine reports were regenerated for this lab — the scan outputs are gitignored by design, so nothing survived from the earlier weeks except the SBOM, which is committed on `feature/lab4` and was used as-is rather than rebuilt (a fresh Syft run would change the `serialNumber` and timestamp and make the Lab 4 comparison meaningless).

**One correction to the lab's parser table.** `auth-report.json` with parser `ZAP Scan` is rejected:

```
Importing ZAP Scan from labs/lab5/results/auth-report.json
  FAILED: HTTP 400 for ZAP Scan (auth-report.json)
    ['Internal error: Wrong file format, please use xml.']
```

DefectDojo 2.58.3's ZAP parser reads **XML**, not the JSON the Lab 5 automation config produces. The fix was to add a `traditional-xml` report job to the ZAP Automation Framework config and re-run the authenticated scan, then import `auth-report.xml`, which returned HTTP 201 with 8 findings. Worth noting that the failed attempt still created an empty test (id 4) — a failed import is not a no-op, and an instance that looks like it has ten tests may have nine with data.

`trivy-k8s.json` imported cleanly and produced **0 findings**, which is correct rather than broken: Lab 7 showed the hardened namespace had zero misconfigurations, and `Trivy Operator Scan` reads the misconfiguration half of that report.

### Active findings by severity

```bash
$ curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?active=true&limit=2000" \
  | jq -c '[.results[].severity] | group_by(.) | map({severity: .[0], count: length})'
```

| Severity | Count |
|---|---:|
| Critical | 44 |
| High | 282 |
| Medium | 280 |
| Low | 54 |
| Info | 13 |
| **Total active** | **673** |

Duplicates reported by DefectDojo: **0**. That is a finding in itself — deduplication is per-engagement and keyed on hash fields that differ between parsers, so the same vulnerability arriving from Grype and from Trivy is not recognised as one issue out of the box. The 673 is a sum of eight tool outputs, not a count of distinct problems.

### Two repeated titles, and what each actually is

**1. `CVE-2026-93748 HTTP-Cache-Semantics 4.2.0` — appears 4 times. This is ONE issue counted four times.**

```json
{"test": 2, "file_path": ".../make-fetch-happen/node_modules/http-cache-semantics/package.json"},
{"test": 2, "file_path": ".../sqlite3/node_modules/http-cache-semantics/package.json"},
{"test": 8, "file_path": ".../make-fetch-happen/node_modules/http-cache-semantics/package.json"},
{"test": 8, "file_path": ".../sqlite3/node_modules/http-cache-semantics/package.json"}
```

How I decided: the four rows carry the same CVE, the same component at the same version, and only two distinct file paths. Tests 2 and 8 are both `Trivy Scan` — Lab 4's run and Lab 7's run against the **same image** — so the ×2 across tests is pure re-import, and the ×2 within each test is the same package vendored at two paths by npm. One upgrade of `http-cache-semantics` closes all four rows.

**2. `javascript.sequelize.security.audit...express-sequelize-injection` — appears 6 times. These are SIX separate findings, and most of them are noise.**

Each row carries a different `file_path` and line: `codefixes/dbSchemaChallenge_1.ts:5`, `codefixes/dbSchemaChallenge_3.ts:11`, `codefixes/unionSqlInjectionChallenge_1.ts:6`, `codefixes/unionSqlInjectionChallenge_3.ts:10`, plus `routes/login.ts:34` and `routes/search.ts:23`. Six genuinely distinct code locations, so DefectDojo is right not to collapse them. But four of the six are under `data/static/codefixes/` — Juice Shop's teaching snippets, which exist to be vulnerable and are never executed by the application. The judgement that matters is not "duplicate or not" but "reachable or not", and DefectDojo cannot make it.

### Which labs produced work, and which produced noise

| Tool | Active | Critical | High |
|---|---:|---:|---:|
| Anchore Grype (Lab 4) | 230 | 18 | 105 |
| Trivy image (Lab 4) | 225 | 14 | 76 |
| Trivy image (Lab 7) | 87 | 11 | 76 |
| Checkov (Lab 6) | 80 | 0 | 0 |
| Semgrep (Lab 5) | 27 | 0 | 13 |
| KICS ansible (Lab 6) | 10 | 0 | 9 |
| ZAP (Lab 5) | 8 | 0 | 1 |
| KICS pulumi (Lab 6) | 6 | 1 | 2 |

**I would act this week on Lab 5 and Lab 7, and on a narrow slice of Lab 4.** Lab 5 contributed eight ZAP findings and twenty-seven Semgrep ones — the smallest numbers on the board and the only ones where a finding came with a working exploit: the ZAP `SQL Injection` on `POST /rest/user/login` and the Semgrep hit at `routes/login.ts:34` are the same defect, and `' OR 1=1--` returns an administrator token. That is one ticket, with a reproduction, that someone fixes on Monday. Lab 7's image scan matters because it carries the fix column: 77 of its 85 findings have a published fixed version, so they are ordinary patch work rather than research. From Lab 4 I would take only the handful of Criticals with fixes available — the same `tar`, `jsonwebtoken` and `libssl3t64` upgrades.

**The noise is Lab 4 and Lab 6 at full volume, for different reasons.** Lab 4's 455 rows across two tools are two views of one image, overlapping heavily, with the same advisory appearing under `GHSA-` and `CVE-` names (Lab 4 documented that) and the same package counted once per vendored copy. Nobody can work a 455-row queue, and the duplication is structural rather than informative. Lab 6's 96 findings are against `vulnerable-iac/` — sample Terraform that is deliberately broken and will never be deployed anywhere; they taught the technique and they describe no real asset. Both belong in the system for trend and coverage purposes, and neither should generate a ticket.

## Task 2

### SLA, mine against the defaults

| Severity | Default | Mine | Why |
|---|---:|---:|---|
| Critical | 7 | **3** | A Critical in this project is not theoretical: Lab 5 produced an unauthenticated administrator login in two requests. Seven days of an exploitable auth bypass on an internet-facing app is not a deadline, it is an acceptance. Three days is survivable by an on-call rotation and still forces the conversation. |
| High | 30 | **14** | Thirty days is a full patch cycle, which is the right number when a High means "a library has a CVE". Most of our Highs are reachable code paths or image packages with a published fix, and shipping a patched image takes hours, not a month. Fourteen matches one sprint. |
| Medium | 90 | **60** | Ninety days outlives the context: by then the person who triaged it has forgotten why, and the finding gets re-triaged from scratch. Sixty keeps it inside the memory of the team that filed it. |
| Low | 120 | **180** | The only number I *lengthened*, deliberately. We will not fix 54 Low findings in four months and pretending otherwise makes the whole SLA a fiction. A longer, honest deadline that we meet is worth more than a short one we silently blow — and it stops Lows from crowding the breach report where the Criticals live. |

Applied via `PATCH /api/v2/sla_configurations/1/`, renamed to `Juice Shop course SLA`.

### Active findings by severity and by source tool

Severity: Critical 44, High 282, Medium 280, Low 54, Info 13 — total 673.
By tool: see the table above. Two observations worth stating: the 44 Criticals come almost entirely from the two dependency scanners (18 Grype + 14 Trivy/Lab 4 + 11 Trivy/Lab 7 = 43 of 44), and the one remaining Critical is KICS's `RDS DB Instance Publicly Accessible` in the Pulumi sample. Not one Critical came from the tools that looked at the running application.

### Three numbers, and how I got them

```bash
$ jq -r '[.results[]|select(.active)|.age] | "min=\(min) max=\(max) median=\(sort|.[length/2|floor])"' f.json
min=0 max=0 median=0

$ jq -r '[.results[]|select(.active)|.sla_days_remaining] | map(select(.!=null))
         | "inside SLA: \(map(select(.>=0))|length) of \(length)"' f.json
inside SLA: 660 of 660
```

| Metric | Value | Method |
|---|---:|---|
| Median age of active findings | **0 days** | `.age` from the findings API, sorted, middle element |
| Age of the oldest active finding | **0 days** | `max` of the same array |
| Share inside SLA | **100 %** (660 of 660 with an SLA date) | count of `sla_days_remaining >= 0` over the non-null set |

**These three numbers are true and almost useless, and saying so is the point.** DefectDojo computes age from the date a finding was *imported*, not the date the defect was *introduced* or *discovered*. Everything landed today, so everything is zero days old and everything is inside its SLA — including the SQL injection that has been in this codebase since 2014 and which I personally found five weeks ago in Lab 5. A programme that reported "100 % SLA compliance" on this instance would be lying with accurate data.

The fix is procedural, not a query: imports must carry the real scan date (`scan_date` on the import endpoint) and, for findings traced to a known release, a `date` reflecting first discovery. Until the pipeline imports on every build rather than once at the end of a semester, age metrics measure the import job, not the risk.

### What Labs 8 and 9 produced that none of these numbers include

Labs 8 and 9 produced **evidence that controls exist, not findings** — a Cosign signature and two attestations over the image digest, and Falco rules that fire at runtime. DefectDojo has no parser for either: an attestation is a positive assertion ("this image's SBOM is authentic"), and the whole data model here is built around negatives. Falco output is a stream of events, not a finite list of defects, so even with a parser the semantics would be wrong.

What I would do about it: track them as **coverage metrics beside the finding counts**, not inside them. Two numbers on the same dashboard — "share of deployed image digests with a verifiable signature and SBOM attestation" and "share of production namespaces with runtime detection reporting" — plus a benchmark entry in the SAMM-style maturity view. The alternative, forcing them into the finding table, would make the dashboard look worse the better the controls got.

### A risk I would accept, with a date

**Accepted:** `CVE-2026-101894` and `CVE-2026-53486` on `decompress@4.2.1` (Critical, no fixed version published), plus `GHSA-5mrr-rgp6-x4gr` on `marsdb@0.6.11` (Critical, unmaintained package).

**Expiry: 2026-12-15**, the engagement end date. At that point this is re-opened whether or not anything has changed — an acceptance without a recheck date is a decision to stop looking.

**Compensating controls, already in place:** the workload runs under the Lab 7 `restricted` Pod Security Standard with a read-only root filesystem, all capabilities dropped and no service-account token, so code execution through a decompression bug lands in a container that cannot write to disk or talk to the Kubernetes API; and the default-deny NetworkPolicy (verified: egress to the internet refused, DNS only) means a payload cannot reach a C2 endpoint. The Lab 9 Falco rule on writes under `/tmp` is the detection backstop for exactly this class of exploit.

**Why accepted rather than fixed:** no patch exists for any of the three. The real remediation is removing `marsdb` and replacing `decompress`, which is application work with its own regression risk, and it is scheduled rather than skipped.

### Executive summary

The project has 673 open findings across eight scanners, but the number that matters is one: an unauthenticated SQL injection on the login endpoint that returns an administrator session in two requests, found independently by a code scanner and a running-app scanner, and reproducible from the command line today. Everything else is either patch work with a published fix (77 of 85 image findings), deliberately vulnerable sample code that will never deploy (96 of the 673), or duplication between tools that report the same defect under different names. To close the gap we need one engineering sprint to parameterise two database queries and ship a rebuilt image, plus a decision on replacing the two unmaintained dependencies that have Critical advisories and no patch.

## Bonus

`submissions/lab10-walkthrough.md`.

### What was hardest to explain concisely

The hardest part to compress was **Lab 7's bonus** — getting Juice Shop to run with `readOnlyRootFilesystem: true`. The fix is a single YAML field, but it only works because of a chain nobody can follow at speaking pace: the app rewrites `index.html` at boot, so the frontend directory must be writable; an empty volume over it hides the entire built frontend and the process exits with `EROFS`; the image is distroless, so there is no shell and no `cp` to seed the volume with; and the way out is an initContainer running the image's own node binary with `fs.cpSync`. Five dependent facts for one checkbox.

What that tells me about documenting the next project is that the write-up needs two layers, not one. The decision layer states what was done and why in one sentence per control, and the mechanism layer sits underneath for whoever has to change it later — because the five facts above are exactly what the next person needs when the app upgrades and the volume list stops matching, and exactly what nobody needs in an interview or a status report. I wrote these labs as a single flat narrative, and the parts that are hardest to summarise now are the ones where the mechanism and the decision are tangled in the same paragraph.
