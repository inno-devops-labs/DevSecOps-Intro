# Lab 10 — Vulnerability Management Capstone

I loaded the nine prescribed scanner reports into DefectDojo **2.58.3**, enabled
deduplication, set remediation deadlines, and recorded a time-limited training
exception. The final snapshot contains **582 active finding records**, including
**34 Critical records overdue** under the new SLA. These are work-queue records,
not 582 independently confirmed vulnerabilities or unique fixes.

## Environment and scope

| Item | Value |
|---|---|
| Snapshot date | 27 September 2026 |
| DefectDojo release | `2.58.3` |
| Source commit | `ea611112772b08b74e6429e833728ce500b4c284` |
| Application images | `defectdojo/defectdojo-django:2.58.3` and `defectdojo/defectdojo-nginx:2.58.3` |
| Deployment | Docker Compose release configuration; HTTP/TLS ports bound to `127.0.0.1` |
| API | `http://127.0.0.1:8080/api/v2/` |
| Product type | `Research and Development`, ID **1** |
| Product | `OWASP Juice Shop`, ID **1** |
| Engagement | `Course Semester Run`, ID **1**, CI/CD, In Progress |
| Engagement dates | 1 September–15 December 2026 |

This branch starts from `main` and adds only this report and the
[five-minute walkthrough](lab10-walkthrough.md). Earlier scanner outputs were
read from local archives rather than copied into their old branch locations.
The DefectDojo checkout, conversion script, API responses, and calculations
remain under the ignored `labs/lab10/work/dd/` directory. This capstone discusses
earlier labs because that is the assignment; their submission files and commits
are not part of this PR.

## Task 1

### Start the pinned release and create its context

```powershell
git clone --branch 2.58.3 --depth 1 https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/work/dd
```

I inspected `docker/setEnv.sh`: its release mode uses the base Compose file
without a development override. The clean clone already had no
`docker-compose.override.yml`, so I used that release configuration directly
on Windows. I also pinned `DJANGO_VERSION=2.58.3` and `NGINX_VERSION=2.58.3`
in the local `.env`; pinning the Git checkout alone would leave the Compose
image defaults at `latest`. I set `COMPOSE_PROJECT_NAME=lab10` and added
`host_ip: 127.0.0.1` to the two published web ports in the ignored checkout.

```powershell
docker compose -f labs/lab10/work/dd/docker-compose.yml --env-file labs/lab10/work/dd/.env up -d --no-build
```

The initializer completed, the login endpoint returned **HTTP 200**, and all
six persistent services were running: nginx, uwsgi, celeryworker, celerybeat,
PostgreSQL, and Valkey. The source's `dojo.__version__` and the deployed
application image tags both identified **2.58.3**. I obtained the token through
`POST /api/v2/api-token-auth/`, reading the generated admin password internally
from the initializer log; neither credential is included in the submission.

I queried `/product_types/` before creating the product and engagement. The
returned type was `Research and Development`, not the importer's outdated
`Engineering` example comment. Imports targeted engagement ID **1** directly,
and engagement-level deduplication scope was enabled.

### Import coverage and parser compatibility

I used the API equivalent of the supplied batch script so the original reports
could stay in their external archives. All nine inputs listed by that script
were present; none was skipped. Diagnostic reruns and temporary proof-of-fix
fixtures were not imported as additional baseline scans, which would mix
different experiment states into the queue.

The important multipart fields for each `POST /api/v2/import-scan/` were:

```text
engagement=1
scan_type=<parser discovered from /api/v2/test_types/>
test_title=<source label in the table below>
scan_date=<original scan date>
minimum_severity=Info
active=true
verified=false
close_old_findings=false
push_to_jira=false
file=<archived report, or the ZAP XML conversion>
```

I checked HTTP status codes and response bodies, then counted persisted findings
through the API. Two adjustments were necessary:

1. **ZAP JSON was rejected.** The exact response was
   `Internal error: Wrong file format, please use xml.` The pinned
   [ZAP parser](https://github.com/DefectDojo/django-DefectDojo/blob/2.58.3/dojo/tools/zap/parser.py)
   requires XML, so I converted `site[].alerts[]` into `site/alerts/alertitem`
   and each `instances[]` item into `instances/instance`. I preserved and
   checked all parser-consumed alert fields and every instance field: **24
   alert groups and 63 instances** survived the conversion. The original JSON
   was unchanged; successful test **5** contains 24 findings, while failed test
   **4** remains empty and contributes nothing to the totals.
2. **The Kubernetes file is Trivy CLI JSON, not Operator CRDs.** Its top-level
   keys are `ClusterName` and `Resources`, which the pinned
   [Trivy parser](https://github.com/DefectDojo/django-DefectDojo/blob/2.58.3/dojo/tools/trivy/parser.py)
   explicitly supports. `Trivy Operator Scan` expects Operator report objects
   with `metadata` and `report`; using it here would return no useful findings.
   I imported the unchanged file with **Trivy Scan** and obtained **152** records.

The ZAP parser also maps `scanner_confidence` from `riskcode` rather than the
source's `confidence` field. I corrected **19** imported confidence values
through the API using the original confidence values and the parser's own
confidence mapping; titles, severities, and counts were unchanged. This kept
a scanner's confidence separate from its severity and from my later verification.

| Source | Original file | Actual parser | Test ID | Imported records | Duplicates after processing | Final active |
|---|---|---|---:|---:|---:|---:|
| L4 Grype | `grype-from-sbom.json` | Anchore Grype | 1 | 183 | 0 | 183 |
| L4 Trivy | `trivy.json` | Trivy Scan | 2 | 177 | 0 | 177 |
| L5 Semgrep | `semgrep.json` | Semgrep JSON Report | 3 | 27 | 0 | 27 |
| L5 ZAP | `auth-report.json` | ZAP Scan | 5 | 24 | 0 | 23 |
| L6 Checkov | `checkov-terraform/results_json.json` | Checkov Scan | 6 | 80 | 0 | 80 |
| L6 KICS Ansible | `kics-ansible/results.json` | KICS Scan | 7 | 10 | 0 | 10 |
| L6 KICS Pulumi | `kics-pulumi/results.json` | KICS Scan | 8 | 6 | 0 | 6 |
| L7 Trivy image | `trivy-image.json` | Trivy Scan | 9 | 76 | 76 | 0 |
| L7 Trivy Kubernetes | `trivy-k8s.json` | Trivy Scan | 10 | 152 | 76 | 76 |
| **Total** | | | | **735** | **152** | **582** |

The remaining difference is one risk-accepted ZAP finding, described in Task 2.
The table counts findings, not raw package matches, HTTP instances, or unique
vulnerabilities; each parser chooses its own grouping.

### Collapse repeat observations

The stock instance returned `enable_deduplication: false` from
`GET /api/v2/system_settings/`. I enabled it with
`PATCH /api/v2/system_settings/1/` and body `{"enable_deduplication": true}`,
then processed existing records:

```powershell
docker exec lab10-uwsgi-1 python manage.py dedupe --dedupe_only --dedupe_sync
```

The API showed this reconciliation:

```text
735 imported records
- 152 duplicate records retained for traceability
= 583 active records after deduplication
-   1 time-limited risk acceptance
= 582 active records in the final snapshot
```

All **76** repeat image-scan records became duplicates, and the Kubernetes scan's
two repeated sets of 76 application findings collapsed to **76** active records.
I did not merge findings solely because their titles matched or overwrite their
original dates to make the queue look younger.

Two concrete repeated-title decisions:

| Repeated title | Evidence and decision |
|---|---|
| `CVE-2023-46233 Crypto-Js 3.3.0` | IDs **246** and **517** have the same CVE, package/version, `juice-shop/node_modules/crypto-js/package.json` path, and hash. Both image reports identify the same immutable Juice Shop digest, `sha256:fd58bdc9745416afce8184ee0666278a436574633ea7880365153a63bfd418b0`. This is the same image issue observed twice; **517** is now inactive with `duplicate_finding=246`. IDs **593** and **669** form another duplicate pair for the same Kubernetes service; **669** points to **593**. The active image and deployment records remain separate contexts, even though a shared dependency update could address both. |
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | This title occurs six times. In particular, **379** is `routes/login.ts:34`, while **382** is `routes/search.ts:23`; they are different live sinks and remain separate active findings. Four other occurrences are teaching-code snippets, not additional live routes. The rule title identifies a pattern, so I used file path, line, and runtime reachability rather than treating all six as duplicates. |

Cross-tool overlap also remains: Grype and Trivy can describe the same dependency
with different identifiers or hashes, and SAST and DAST evidence can describe
the same underlying defect. Therefore **582 is not a claim of 582 unique root
causes**. The next triage pass should link shared remediation work while retaining
source evidence and deployment context.

### Active findings by severity

I paginated `GET /api/v2/findings/?test__engagement=1&active=true&limit=200`
until `next` was null and grouped the resulting records by `severity`.

| Severity | Active records |
|---|---:|
| Critical | 34 |
| High | 244 |
| Medium | 241 |
| Low | 50 |
| Info | 13 |
| **Total** | **582** |

Lab 5 contributes the clearest immediate application work: the public product-search
SQL injection has matching source and dynamic evidence, while some teaching-snippet
and header alerts need context before they become tickets. Lab 6 contributes
actionable wildcard-IAM and infrastructure exposure findings, and Labs 4 and 7
contribute dependency upgrade work, although repeated scans of the same image
inflate the raw total. Labs 1 and 2 provide deployment and threat-model context,
and Lab 3 provides repository safeguards; none has a scanner file in this import
set, so absence from the total does not mean absence of value. Labs 8 and 9
provide signing, attestation, policy, and runtime evidence rather than parser-ready
vulnerability findings; those need separate control tracking, not invented CVEs.

## Task 2

### Set and apply remediation deadlines

I changed SLA configuration **1**, already assigned to product **1**, through
`PATCH /api/v2/sla_configurations/1/`:

```json
{"critical": 3, "high": 14, "medium": 30, "low": 90}
```

All four `enforce_*` flags remain true. SLA enforcement was already enabled
globally, and I verified the recalculated `sla_expiration_date` and
`sla_days_remaining` values through the findings API after the update.

| Severity | Stock default | Chosen deadline | Reason |
|---|---:|---:|---|
| Critical | 7 days | **3 days** | Shorten the window for the highest-impact issues; require immediate triage and containment while a fix is prepared. |
| High | 30 days | **14 days** | Keep serious application and infrastructure defects within one two-week delivery cycle instead of waiting a month. |
| Medium | 90 days | **30 days** | Reserve capacity in the next monthly maintenance cycle so configuration debt does not accumulate for a quarter. |
| Low | 120 days | **90 days** | Address lower-impact work in a quarterly batch while retaining a firm review date. |

Info has no enforced deadline in this configuration. These are a proposed
operating policy demonstrated in the local instance, not a claim that an
external production owner approved them. Imported severity is a triage input:
for example, all **80** Checkov findings arrived as Medium, which does not make
a wildcard IAM policy less urgent than a Low-confidence web alert labeled High.

I marked the two corroborating product-search records, **382** (Semgrep) and
**389** (ZAP), verified and set `planned_remediation_date=2026-09-30`, with a
shared `search-sql-injection` tag. They describe one priority remediation item
with two evidence sources, not two independent completed fixes. The proposed
application owner must parameterize the query and demonstrate that normal
search still works and the bypass payload cannot reveal hidden rows before
either record is closed.

### Active findings by source tool

The severity totals above and this table use the same final snapshot.
Each record is attributed to its originating test's `scan_type`, not counted
once for every entry in `found_by`, so the rows add up to **582**.

| Source parser | Critical | High | Medium | Low | Info | Total |
|---|---:|---:|---:|---:|---:|---:|
| Anchore Grype | 14 | 85 | 65 | 12 | 7 | 183 |
| Trivy Scan | 20 | 132 | 70 | 31 | 0 | 253 |
| Semgrep JSON Report | 0 | 13 | 14 | 0 | 0 | 27 |
| ZAP Scan | 0 | 3 | 10 | 6 | 4 | 23 |
| Checkov Scan | 0 | 0 | 80 | 0 | 0 | 80 |
| KICS Scan | 0 | 11 | 2 | 1 | 2 | 16 |
| **Total** | **34** | **244** | **241** | **50** | **13** | **582** |

The 253 active Trivy records comprise **177** image findings from the earlier
scan plus **76** deployment-context findings. The newer standalone image scan
contributes duplicate evidence rather than an additional active queue.

### Age and SLA compliance

I supplied the original scan dates at import: **20 September** for the SBOM/image
and Semgrep scans, **21 September** for the authenticated ZAP report, and
**23 September** for IaC and the later image/Kubernetes scans. These dates came
from saved report metadata and archived run records; for Semgrep, whose JSON
does not contain a scan timestamp, I used the preserved report modification
date. They represent first observation in this retained dataset, not the date
each vulnerability first existed.

The calculation date is **2026-09-27**. No accepted or duplicate records are
included in the active-age denominator, and I checked computed ages against
the API's `age` field.

```python
from collections import Counter
from datetime import date
from statistics import median

# api_get sends Authorization: Token <token kept in the environment>.
def fetch_all(url):
    rows = []
    while url:
        page = api_get(url)
        rows.extend(page["results"])
        url = page["next"]
    return rows

active = fetch_all(
    DD_URL + "/api/v2/findings/?test__engagement=1&active=true&limit=200"
)
as_of = date(2026, 9, 27)
ages = [max(0, (as_of - date.fromisoformat(f["date"])).days) for f in active]
assert ages == [f["age"] for f in active]
median_age = median(ages)
oldest_age = max(ages)
enforced = [f for f in active if f["sla_days_remaining"] is not None]
inside = [f for f in enforced if f["sla_days_remaining"] >= 0]
sla_compliance = 100 * len(inside) / len(enforced)
```

| Metric | Result | Calculation |
|---|---|---|
| Median active age | **7 days** | Median of all 582 active ages; sorted positions 291 and 292 are both 7. |
| Oldest active age | **7 days** | Maximum age; earliest retained finding date is 20 September. |
| Inside SLA, among records with an enforced deadline | **94.02%** | `535 / 569 × 100`; a deadline of today counts as inside SLA. |
| Inside SLA as a share of all active records | **91.92%** | `535 / 582 × 100`; the 13 Info records have no deadline and are not labeled compliant or overdue. |

The age histogram is **172 at 4 days, 23 at 6 days, and 387 at 7 days**.
There are **34 overdue records**, all Critical, and **13 without an enforced
SLA**. For example, finding **246** was observed on 20 September, received a
23 September deadline under the three-day Critical SLA, and returned
`sla_days_remaining=-4`. Shortening the SLA exposed an existing backlog; the
94.02% figure is a snapshot, not evidence of a successful historical fix rate.

### Account for control evidence and accepted risk

Labs 8 and 9 produced signature/attestation verification, policy decisions,
and runtime alerts that these vulnerability metrics do not include; I would
link them to the product and release digest in a separate control-evidence
register, with an owner, retention period, and regular verification schedule.

I created full risk acceptance **1** for ZAP finding **405**, **Private IP
Disclosure**, severity **Low**:

| Decision field | Recorded value |
|---|---|
| Scope | Disposable, local training target only; not production approval. |
| Owner / approval | Local admin owns the record; `Lab exercise owner (simulated approval)` makes the exercise status explicit. |
| Expiry | **27 October 2026, 23:59:59 UTC**. |
| Compensating control | Bind the target to loopback, use synthetic training data, prohibit public exposure and real credentials, and stop the disposable instance when unused. |
| Early review trigger | Any change in exposure or use outside the isolated lab. |
| Expiry behavior | `reactivate_expired=true`, `restart_sla_expired=false`; do not erase the original remediation clock. |
| API verification | `active=false`, `risk_accepted=true`; excluded from the 582 active records but retained among the 735 total records. |

This exception does not accept the SQL injection, dependency vulnerabilities,
or infrastructure findings. The target instance was already stopped; the
record documents the conditions under which a temporary local training
exception would remain valid.

### Executive summary

The project has **582 active finding records**, **34 overdue Critical records**,
and **94.02% compliance among records with an enforced SLA**, after removing
152 repeat observations and documenting one expiring training exception.
The strongest confirmed application risk is unauthenticated product-search
SQL injection, because source analysis and a live follow-up demonstrate a
query-logic bypass rather than only a scanner label.
I need an application owner and a tested parameter-binding change by
**30 September 2026**, alongside a platform owner to triage the overdue Critical
dependency queue and record fixes or explicitly time-limited exceptions.

## Bonus

The [walkthrough](lab10-walkthrough.md) is written for approximately five minutes
at a conversational speaking pace. The hardest part to explain concisely was
why 735 observations became 582 active records without claiming that we fixed
153 vulnerabilities. That distinction depends on duplicate scope, parser behavior,
risk acceptance, and the difference between a finding and a root cause.
For the next project, I would record source identity, first-seen date, affected
asset, decision, owner, and closure evidence together from the first scan.
That would let a short management summary stay traceable without carrying
the whole scanner history into every presentation.

## Final validation and cleanup

- Nine successful report imports, with parser names and persisted counts checked.
- Pagination completed for every metric query; severity and tool totals both sum to 582.
- All 152 duplicates are inactive and retain links to originals.
- SLA values were read back after the update; ages and deadlines were checked against API fields.
- The accepted finding has an expiry and remains visible outside the active queue.
- Credentials, raw findings, and the DefectDojo checkout are excluded from the PR.

After exporting the evidence, I removed this disposable stack and its volumes:

```powershell
docker compose -f labs/lab10/work/dd/docker-compose.yml --env-file labs/lab10/work/dd/.env down -v
```

The live instance is therefore no longer available. Finding IDs in this report
refer to the captured local run, whose API snapshots remain in the ignored
working directory; the submission preserves its counts, decisions, and methods.
