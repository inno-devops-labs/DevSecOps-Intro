# Lab 10 — Vulnerability Management: The Capstone

Branch: `feature/lab10`. Executed on 2026-10-10. Task 1, the optional Task 2, and
the bonus are all done. Bonus walkthrough: [`lab10-walkthrough.md`](lab10-walkthrough.md).

| Component             | Version                                                                                                                     | How it ran                                                                             |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| DefectDojo            | **2.58.3** (`dojo.__version__` inside `uwsgi`; UI footer `v. 2.58.3`)                                                       | `git clone --branch 2.58.3 --depth 1` (commit `ea61111`), `./docker/setEnv.sh release` |
| Django / nginx images | `defectdojo/defectdojo-django:2.58.3@sha256:22f6218b…e78b887`, `defectdojo/defectdojo-nginx:2.58.3@sha256:d1ba80db…d88e25b` | Docker Compose, release profile                                                        |
| PostgreSQL / Valkey   | `postgres:18.3-alpine`, `valkey/valkey:9.0.3-alpine`                                                                        | digest-pinned in the 2.58.3 compose file                                               |
| jq                    | 1.8.1 (`.venv/lab4/jq.exe` from Lab 4)                                                                                      | host                                                                                   |
| Docker                | Engine 29.7.2, Compose v5.5.1                                                                                               | host (Windows 11, Docker Desktop)                                                      |

All seven containers started; `initializer` exited 0 after the migrations.
Product `OWASP Juice Shop` (id 1, type `Research and Development`) and engagement
`Course Semester Run` (id 1) were created with the 10.3 commands unchanged.

### Where this run departs from the lab text

1. **`docker compose up -d` alone does not run 2.58.3.** At the pinned tag the
   compose file says `image: "defectdojo/defectdojo-django:${DJANGO_VERSION:-latest}"`
   (nginx likewise), and nothing sets the variable, so the pinned clone pulls
   whatever `latest` is, which is 3.x. I started it as
   `DJANGO_VERSION=2.58.3 NGINX_VERSION=2.58.3 docker compose up -d --no-build`.
2. **Deduplication is off on a stock instance.** `GET /system_settings/` returned
   `"enable_deduplication": false`. I set it to `true` through the API before the
   first import. Otherwise nothing collapses, whatever the hash says.
3. **The ZAP import failed.** The 2.58.3 `ZAP Scan` parser refuses any file not
   named `*.xml` (`Internal error: Wrong file format, please use xml.`), and Lab 5
   kept only the JSON and HTML reports. ZAP's traditional JSON and XML reports
   serialize the same alert model, so I copied it field for field into the XML
   layout (`labs/lab10/work/zap-json-to-xml.py`; 22 alerts, 59
   instances in and out). Then I re-imported it into the same, empty test 4 with
   `/reimport-scan/`.
4. **`trivy-k8s.json` imported "ok" with zero findings.** `Trivy Operator Scan`
   reads trivy-operator CRD objects (`metadata.labels` plus `report`). The
   `trivy k8s` CLI writes `{ClusterName, Resources}`, so the parser returns an
   empty list and the API answers 201. The `ClusterName`/`Resources` branch is
   in the plain `Trivy Scan` parser (`dojo/tools/trivy/parser.py:176–232`). I
   imported the same file again as `Trivy Scan` (test 10) and kept the empty
   test 9 as evidence.
5. **Every finding was dated on the day it was imported.** None of the seven
   parsers reads a date from its report, and the importer sends no `scan_date`.
   All 754 findings were therefore dated 2026-10-10, with age 0. Task 2 explains
   how I corrected this.

## Task 1

### What was imported

`bash labs/lab10/imports/run-imports.sh` printed the parser names discovered
from the instance (all seven matched the table in 10.4) and exited 1 for the ZAP
failure. Counts are the API's `statistics.after.total`, then the state once
deduplication had finished:

| Lab | File                                                  | Parser              | Test |                    Imported | Marked duplicate |  Active |
| --- | ----------------------------------------------------- | ------------------- | ---: | --------------------------: | ---------------: | ------: |
| 4   | `grype-from-sbom.json`                                | Anchore Grype       |    1 |                         183 |                0 |     183 |
| 4   | `trivy.json`                                          | Trivy Scan          |    2 | 177 (173 vulns + 4 secrets) |                0 |     177 |
| 5   | `semgrep.json`                                        | Semgrep JSON Report |    3 |                          27 |                0 |      27 |
| 5   | `auth-report.json`                                    | ZAP Scan            |    4 |             **HTTP 400, 0** |                – |       – |
| 5   | `auth-report.xml` (converted, reimported into test 4) | ZAP Scan            |    4 |                          22 |                0 |      22 |
| 6   | `checkov-terraform/results_json.json`                 | Checkov Scan        |    5 |                          80 |                0 |      80 |
| 6   | `kics-ansible/results.json`                           | KICS Scan           |    6 |                          10 |                0 |      10 |
| 6   | `kics-pulumi/results.json`                            | KICS Scan           |    7 |                           6 |                0 |       6 |
| 7   | `trivy-image.json`                                    | Trivy Scan          |    8 |   83 (81 vulns + 2 secrets) |               72 |      11 |
| 7   | `trivy-k8s.json`                                      | Trivy Operator Scan |    9 |                       **0** |                – |       0 |
| 7   | `trivy-k8s.json` (by hand)                            | Trivy Scan          |   10 | 166 (162 vulns + 4 secrets) |               83 |      83 |
|     | **Total**                                             |                     |      |                     **754** |          **155** | **599** |

Every count matches the raw report: Grype `.matches` 183, Semgrep `.results` 27,
ZAP 22 alerts, Checkov 80 failed checks, KICS 10 and 6 file entries, Trivy
vulnerabilities plus secrets. No report was missing, so the importer printed no
`SKIP` lines.

### Active findings by severity

The 10.5 query, verbatim output:

```text
[{"severity":"Critical","count":37},{"severity":"High","count":258},{"severity":"Info","count":13},{"severity":"Low","count":50},{"severity":"Medium","count":241}]
```

| Critical | High | Medium | Low | Info | **Total active** |
| -------: | ---: | -----: | --: | ---: | ---------------: |
|       37 |  258 |    241 |  50 |   13 |          **599** |

(Of 754 findings in total, 155 are inactive duplicates. Task 2's risk acceptance
later takes this to 590.)

### Two repeated titles

The 10.5 title query returns, alphabetically:

```text
[{"title":"CVE-2015-9235 Jsonwebtoken 0.1.0","n":4},{"title":"CVE-2015-9235 Jsonwebtoken 0.4.0","n":4},{"title":"CVE-2016-1000223 JWS 0.2.6","n":4},{"title":"CVE-2017-18214 Moment 2.0.0","n":4},{"title":"CVE-2018-16487 Lodash 2.4.2","n":4}]
```

**`CVE-2015-9235 Jsonwebtoken 0.1.0` × 4: one issue. It is five rows in total
and three of them are active: two under this title, plus one Grype row under
another title.**

| Finding | Test | Source                                                                                    | Active | Duplicate of | `hash_code`     |
| ------: | ---: | ----------------------------------------------------------------------------------------- | ------ | -----------: | --------------- |
|     265 |    2 | Trivy, Lab 4 `docker save` archive                                                        | yes    |            – | `878f89d0598d…` |
|     510 |    8 | Trivy, Lab 7, same archive                                                                | no     |          265 | `878f89d0598d…` |
|     615 |   10 | Trivy, Lab 7 cluster, first container of the pod                                          | yes    |            – | `8921b78764fd…` |
|     698 |   10 | Trivy, Lab 7 cluster, second container (app and seeding initContainer run the same image) | no     |          615 | `8921b78764fd…` |

A fifth row has a different title: Grype's finding 3,
`GHSA-c7hr-j4mj-j2w6 in jsonwebtoken:0.1.0`, whose `vulnerability_ids` contains
`CVE-2015-9235`. How I decided it is one issue: all five rows name the same
package copy (`node_modules/express-jwt/node_modules/jsonwebtoken`, version
0.1.0), the same advisory, and the same image. The Lab 4 archive, the Lab 7
archive, and the pod's pinned image are all digest `fd58bdc9…`. Deduplication
caught the rescan of the same archive and the second container of the same pod.
It missed the cluster copy, although 265 and 615 have byte-identical title,
severity, CWE, IDs and description, the five `Trivy Scan` hash fields.
DefectDojo adds `service` to every hash (`HASH_CODE_FIELDS_ALWAYS = ["service"]`,
`dojo/settings/settings.dist.py:1179`). The Trivy parser sets `service` to
`juice-shop / Deployment / juice-shop` for a cluster scan and leaves it empty for
an image scan. For OS packages the description differs as well: `**Target:**` is
`/image.tar (debian 13.4)` in one and `bkimminich/juice-shop@sha256:fd58bdc9… (debian 13.4)`
in the other. Each of the 83 active cluster rows has a same-title twin from an
image scan, so all of test 10 is double counting. Grype is never compared with
Trivy, because each parser hashes different fields under a different title
format. The neighbouring `… Jsonwebtoken 0.4.0` title is a **separate** finding:
a second copy of the library (`node_modules/jsonwebtoken`), which needs its own
upgrade.

**`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
× 6, all Semgrep, all active and High: six separate findings, not duplicates.**

| Finding | Location                                                                                                                                                 |
| ------: | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
|     382 | `routes/search.ts:23`                                                                                                                                    |
|     379 | `routes/login.ts:34`                                                                                                                                     |
| 371–374 | `data/static/codefixes/dbSchemaChallenge_1.ts:5`, `dbSchemaChallenge_3.ts:11`, `unionSqlInjectionChallenge_1.ts:6`, `unionSqlInjectionChallenge_3.ts:10` |

How I decided: each row has a distinct `file_path:line` and hash, so each is its
own place in the code. Fixing `search.ts` does nothing for `login.ts`. The four
`codefixes` files are the coding-challenge snippets that Juice Shop serves as
text, not routed handlers, so they are noise in context, not duplicates. The two
handlers are real: Lab 5 confirmed `search.ts` with a boolean pair (0, then 56,
then 0 rows, with no session). They are also the only place where two tools agree.
ZAP's `SQL Injection` (finding 568) has exactly these two endpoints,
`/rest/products/search` and `/rest/user/login`. So two bugs appear as three rows
from two tools, and DefectDojo cannot link SAST and DAST rows.

### Which labs mattered

This week I would act on Lab 5 and a short list from Labs 4 and 7. The
product-search SQL injection is the one finding confirmed by two tools and by
hand, `login.ts:34` is the same bug on the login path, and the RSA key Trivy
found in `lib/insecurity.ts` lets anyone sign a valid admin JWT today. In the
dependency scans, only the 15 distinct Critical issues behind the 37 Critical
rows need action this week: five upgrades plus two packages with no fix. They
are led by `jsonwebtoken` 0.1.0/0.4.0, which sits in the authentication path and
has the highest EPSS of the Criticals (0.087). The noise is double counting and
scope. Labs 4 and 7 put 454 of the 599 rows on one image digest, about 2.3 rows
per distinct issue (199). Lab 6 adds 96 rows about a Terraform/Ansible/Pulumi
fixture that deploys nothing in this project; 80 of them are Medium only because
the Checkov parser turns `severity: null` into `"Medium"`
(`dojo/tools/checkov/parser.py:144`). Labs 1–3, 8 and 9 add no rows at all.
Their output is controls, not defects, so this one number cannot say whether
those controls work.

## Task 2

### SLA

The 10.6 query before the change:

```text
Default: critical=7 high=30 medium=90 low=120
No SLA Enforced: critical=7 high=30 medium=90 low=120
```

I changed the `Default` configuration, which product 1 uses, through the API:

```bash
curl -s -X PATCH "$DD_URL/api/v2/sla_configurations/1/" \
  -H "Authorization: Token $DD_TOKEN" -H 'Content-Type: application/json' \
  -d '{"critical":3,"high":14,"medium":60,"low":180}'
```

After the change: `Default: critical=3 high=14 medium=60 low=180`. Celery
recalculated every finding's `sla_expiration_date` in about 2 s
(`async_update_sla_expiration_dates_sla_config_sync … succeeded`).

| Severity | Default |    Mine | Why mine differs                                                                                                                                                                                                                                                                                                               |
| -------- | ------: | ------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Critical |       7 |   **3** | Most Criticals are fixed by bump → rebuild → sign → admit, which takes about a day when it works. Three days is enough to ship that, or to make the decision explicit: re-rate with a `severity_justification`, or risk-accept with an expiry. Seven days mostly buys a second weekend of exposure for an internet-facing app. |
| High     |      30 |  **14** | 226 of the 258 active Highs have a fixed version and collapse into routine upgrades. 14 days is one sprint, so a High found in one sprint is closed by the end of the next. Thirty days leaves a published, patch-diffable fix unapplied for a month.                                                                          |
| Medium   |      90 |  **60** | The 237 Mediums are 131 dependency CVEs (cleared by the same upgrades as the Highs), 80 unrated Checkov checks, and ZAP's CSP and header items. Sixty days is two monthly dependency-refresh cycles, so a Medium may survive one missed cycle but not two.                                                                     |
| Low      |     120 | **180** | The 50 Lows (43 low-rated dependency CVEs, plus cookie flags, timestamp disclosure and one unpinned package) are fixed in batches when their package is touched anyway. A 120-day clock on them makes breach noise that teaches people to ignore the SLA report. 180 days matches FedRAMP's Low deadline.                      |

Info keeps no SLA, which is the stock behaviour. Severity is the scanner's as
imported. The clock only makes sense if triage owns severity, so I would raise
the confirmed SQL injection and the leaked signing key to Critical. They are
High as imported, and I left them unchanged so that the numbers below stay
reproducible from the reports.

### Active findings by severity and source tool

After the risk acceptance below (590 active):

```bash
T=$(curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/tests/?limit=100" \
  | jq -c '[.results[] | {key: (.id|tostring), value: .scan_type}] | from_entries')
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?active=true&limit=1000" \
  | jq -r --argjson t "$T" '.results | group_by(.test)[] | [$t[.[0].test|tostring], .[0].test,
      (map(select(.severity=="Critical"))|length), (map(select(.severity=="High"))|length),
      (map(select(.severity=="Medium"))|length), (map(select(.severity=="Low"))|length),
      (map(select(.severity=="Info"))|length), length] | @tsv'
```

| Source (lab, test)           | Critical |    High |  Medium |    Low |   Info |   Total |
| ---------------------------- | -------: | ------: | ------: | -----: | -----: | ------: |
| Anchore Grype (L4, 1)        |       13 |      85 |      63 |     12 |      7 |     180 |
| Trivy Scan, image (L4, 2)    |        9 |      66 |      68 |     31 |      0 |     174 |
| Semgrep JSON Report (L5, 3)  |        0 |      13 |      14 |      0 |      0 |      27 |
| ZAP Scan (L5, 4)             |        0 |       2 |      10 |      6 |      4 |      22 |
| Checkov Scan (L6, 5)         |        0 |       0 |      80 |      0 |      0 |      80 |
| KICS Scan, Ansible (L6, 6)   |        0 |       9 |       0 |      1 |      0 |      10 |
| KICS Scan, Pulumi (L6, 7)    |        0 |       2 |       2 |      0 |      2 |       6 |
| Trivy Scan, image (L7, 8)    |        1 |       9 |       0 |      0 |      0 |      10 |
| Trivy Scan, cluster (L7, 10) |        9 |      72 |       0 |      0 |      0 |      81 |
| **Total**                    |   **32** | **258** | **237** | **50** | **13** | **590** |

Grouped by tool: Trivy 265, Grype 180, Checkov 80, Semgrep 27, ZAP 22, KICS 16.
Matching dependency rows across tools by package, version and advisory ID
(GHSA↔CVE aliases from `vulnerability_ids`) reduces the 445 Grype/Trivy rows to
**195 distinct issues**, so about 340 distinct issues sit behind the 590 rows.
The 32 Critical rows are 13 issues in 10 package versions.

### Age and SLA: three numbers

**First, fix the clock.** As imported, DefectDojo reported median age **0**,
oldest **0**, and **100 %** (586/586) inside SLA. That is true but meaningless:
`date`, from which DefectDojo computes `age` and the SLA, held the import day.
I set each finding's `date` to its report's scan date (UTC):

| Tests           | Scan date  | Source of the date                                                                                                             |
| --------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------ |
| 1, 2 (Lab 4)    | 2026-09-18 | Grype `.descriptor.timestamp` 19:14:32Z; Trivy `.CreatedAt` 19:05:21Z                                                          |
| 3–7 (Labs 5, 6) | 2026-09-24 | ZAP `@generated` 21:37:30; KICS `.start` 22:21Z; Semgrep and Checkov JSON have no timestamp, files written 21:02 and 22:22 UTC |
| 8, 10 (Lab 7)   | 2026-10-01 | Trivy `.CreatedAt` 21:46:56Z; `trivy-k8s.json` written 22:18 UTC                                                               |

```bash
# id<TAB>test for all 754 findings; tr strips the CR that jq.exe emits on Windows
curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?limit=1000" \
  | jq -r '.results[] | "\(.id)\t\(.test)"' | tr -d '\r' |
while IFS=$'\t' read -r id t; do
  case $t in 1|2) d=2026-09-18;; 3|4|5|6|7) d=2026-09-24;; *) d=2026-10-01;; esac
  curl -s -o /dev/null -X PATCH "$DD_URL/api/v2/findings/$id/" -H "Authorization: Token $DD_TOKEN" \
    -H 'Content-Type: application/json' -d "{\"date\":\"$d\"}"
done
```

All 754 PATCHes returned 200. `active`, `duplicate` and `hash_code` were
compared before and after and did not change. The lasting fix is one line in
the importer, sending `-F "scan_date=…"` read from each report.

Then I ran
`A=$(curl -s -H "Authorization: Token $DD_TOKEN" "$DD_URL/api/v2/findings/?active=true&limit=1000")`,
and each query below as `echo "$A" | jq …`:

| Metric                              | Value                    | Query                                                                                                                                           |
| ----------------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Median age of active findings       | **22 days**              | `jq '[.results[].age] \| sort \| if length % 2 == 1 then .[(length - 1) / 2] else (.[length / 2 - 1] + .[length / 2]) / 2 end'`                 |
| Oldest active finding               | **22 days** (2026-09-18) | `jq -c '[.results[] \| {age, date}] \| max_by(.age)'`                                                                                           |
| Share of active findings inside SLA | **63.8 %** (368 of 577)  | `jq -c '[.results[] \| select(.sla_expiration_date != null)] \| {with_sla: length, inside: (map(select(.sla_days_remaining >= 0)) \| length)}'` |

Ages are 22 days for 354 findings (Lab 4), 16 for 145 (Labs 5 and 6), and 9 for
91 (Lab 7). The median and the oldest are both 22 because Lab 4 alone is more
than half of the active rows. "Oldest" is a 354-way tie. Of the 81 cluster-scan
rows, 75 show 9 days but are issues Lab 4 already found on 2026-09-18. They look
younger only because the hash failed to collapse them. The other 6 are
advisories that first appeared in the 2026-10-01 Trivy database.

The SLA share excludes the 13 Info findings, which have no SLA in DefectDojo.
By severity: **Critical 0/32** (6 to 19 days over), **High 81/258** (only Lab 7's
nine-day-old rows are inside 14 days; everything from Labs 4–6 is over),
Medium 237/237, Low 50/50. The confirmed SQL injection (ZAP 568, Semgrep 382 and 379) is High, 16 days old, and 2 days past its SLA. Under the stock 7/30/90/120
the same findings score **94.5 %** (545/577): only the Criticals are late.

### What Labs 8 and 9 add that these numbers cannot see

Labs 8 and 9 produced controls rather than defects: a Cosign signature, CycloneDX
and SLSA attestations bound to digest `28870b9d…` with a tamper test that
verification caught, Conftest rules passing 34/34 on the hardened manifest, and
Falco rules with their alerts. So none of the numbers above can say whether the
running pod is the signed digest or whether something unexpected executed in
it. I would report control coverage next to them (share of deploys admitted with
a verified signature and zero policy failures, Falco alerts triaged within a
day). I would also feed violations into DefectDojo so that they get an owner and
a date: Conftest through the SARIF parser (`conftest test -o sarif`), Falco
through Generic Findings Import, since DefectDojo has no Falco parser.

### Risk acceptance

**Accepted: `decompress@4.2.1`, 9 active rows, 4 advisories, no fixed version
published.** The advisories are CVE-2026-53486 and CVE-2026-101894 (Critical),
plus CVE-2026-10732 and CVE-2026-39243 (Medium). The rows are findings 28, 97,
148, 249, 250, 251, 501, 606 and 607, across Grype and Trivy. Recorded in
DefectDojo as risk acceptance 1: decision _Mitigate_, owner `admin`, accepted by
the Juice Shop service owner. It **expires 2027-01-08**, with
`reactivate_expired: true` and `restart_sla_expired: false`, so if nothing has
changed by then the findings come back already overdue.

- **Why it is not reachable.** `decompress` arrives only through `download@8.0.0`,
  a direct dependency. That package calls it only when `opts.extract` is set
  (`node_modules/download/index.js:80` and `:86`, read from the running image).
  Juice Shop calls `download(url)` with no options (`lib/utils.ts:119`), and only
  at startup, for URLs from operator configuration (`lib/startup/customizeApplication.ts:78`,
  `customizeEasterEgg.ts:17`). Request input never reaches it.
- **Compensating controls** (all from Lab 7 and running):
  - `readOnlyRootFilesystem: true`, so a path-traversal write fails with `EROFS`
    outside six size-limited emptyDirs
  - UID 65532, all capabilities dropped, no ServiceAccount token
  - default-deny egress, so `download()` cannot fetch an archive from outside at runtime
  - Lab 9's Falco rules, which alert on unexpected writes and on executing a dropped binary
- **The condition the acceptance relies on must be tested, not assumed.** The
  acceptance requires adding a Semgrep rule to CI that fails the build if any
  call to `download(…)` passes `extract`; that rule does not exist yet. The
  acceptance ends early on a fixed release or a new `decompress` advisory.
- **The real fix**, owned by the app team before expiry: replace `download` with
  Node 24's built-in `fetch` in `lib/utils.ts`, which removes `download` and
  `decompress` from the image.

What I would **not** accept: `marsdb@0.6.11` (GHSA-5mrr-rgp6-x4gr, Critical, no
fix) is reachable. `routes/showProductReviews.ts:36`, `trackOrder.ts:18` and
`chat.ts:147` build `$where` strings from request input. It needs replacing,
not a signature.

### Executive summary

Juice Shop has 590 open findings, which reduce to about 340 distinct issues once
three scans of the same image are matched; 64 % of the findings with a deadline
are inside it, but none of the 32 Critical findings is (oldest 22 days against a
3-day deadline). The single biggest risk is the public product search: an
unauthenticated SQL injection, confirmed by two scanners and by hand and open
for 16 days, that lets anyone read the entire database, including users'
password hashes. Closing it needs one engineer for about a week to ship the
already-tested five-line query fix and the five dependency upgrades behind 29 of
the 32 Critical rows, plus your decision that we maintain our own patched build
of Juice Shop instead of waiting for upstream releases, because every fix to
this image depends on that.

## Bonus

The walkthrough is in [`lab10-walkthrough.md`](lab10-walkthrough.md), about 700
words.

The hardest part to explain concisely was the dependency findings from Labs 4
and 7. Every true sentence about them needs a qualifier (which digest, which
platform, which scanner database date, GHSA or CVE), and the walkthrough only
worked once I replaced "183 versus 173" with "one image, about 200 distinct
issues, five upgrades". The SQL injection, by contrast, took one paragraph,
because Lab 5 kept the request, the response, the source line and the confirming
boolean pair together. For the next project I would keep a findings ledger from
day one, keyed by issue (package plus advisory, or file plus line), with the
evidence and the detection date beside each entry, instead of per-tool reports.
Then age, SLA and "how many problems do we have" are true at the first import
rather than reconstructed afterwards.

## Notes

- The stack is still running at `http://localhost:8080` with everything above
  loaded. Remove it with `docker compose down -v` from `labs/lab10/work/dd`.
- Not committed: `labs/lab10/work/` (the DefectDojo clone and the ZAP
  converter), `labs/lab10/imports/import-*.json` (the API responses), and
  `labs/lab5/results/auth-report.xml`. The latter two are git-ignored.
- Two smaller parser problems seen along the way:
  - The ZAP parser takes `scanner_confidence` from `riskcode` instead of
    `confidence` (`dojo/tools/zap/parser.py:90–91`). The SQL injection ZAP rated
    "High (Low)" is therefore stored as confidence 1, "Certain".
  - KICS file paths keep the container mount prefix (`../../path/vulnerable-iac/…`).
