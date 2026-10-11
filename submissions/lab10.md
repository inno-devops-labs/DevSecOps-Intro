# Lab 10 — Vulnerability Management: The Capstone

Environment: Windows + Docker Desktop 29.8.2 (WSL2 6.6 kernel), Docker Compose v5.5.1. Everything below was run through `labs/lab10/lab10-run.ps1` + `labs/lab10/lab10-fix.ps1` (PowerShell ports of 10.1–10.6, same API calls as the lab's `curl`/`jq` steps; they are not part of the PR). Numbers were computed from the API dumps (`/api/v2/tests/`, `/api/v2/findings/`, `/api/v2/sla_configurations/`) taken at **2026-10-11 ~23:45 UTC**.

## Task 1

### 10.1–10.3 Instance

```
$ git clone --branch 2.58.3 --depth 1 https://github.com/DefectDojo/django-DefectDojo.git dd   # + setEnv.sh release (no override file)
$ docker compose ps
celerybeat     defectdojo/defectdojo-django:2.58.3   Up
celeryworker   defectdojo/defectdojo-django:2.58.3   Up
initializer    defectdojo/defectdojo-django:2.58.3   Exited (0)
nginx          defectdojo/defectdojo-nginx:2.58.3    Up   0.0.0.0:8080->8080/tcp
postgres       postgres:18.3-alpine@sha256:5445…     Up
uwsgi          defectdojo/defectdojo-django:2.58.3   Up
valkey         valkey/valkey:9.0.3-alpine@sha256:e109… Up
$ docker compose exec -T uwsgi python -c "import dojo; print(dojo.__version__)"
2.58.3
```

**DefectDojo 2.58.3.** One trap the lab does not mention: the pinned clone's `docker-compose.yml` still says `image: defectdojo/defectdojo-django:${DJANGO_VERSION:-latest}`, so pinning the *clone* alone runs whatever `latest` is. I exported `DJANGO_VERSION=2.58.3` and `NGINX_VERSION=2.58.3` so code, images and parser names agree.

Product type `1 Research and Development`; `product=1`, `engagement=1` ("Course Semester Run", CI/CD). Before importing I turned on **deduplication** (`PATCH /system_settings/1/ {"enable_deduplication": true}` — it is off on a stock instance) and passed each report's own date as `scan_date`, so a finding's age means "known since the scan", not "imported tonight".

### 10.4 Imports

| Lab | File | Parser | Findings | Active after dedup |
|---|---|---|---:|---:|
| 4 | `grype-from-sbom.json` | Anchore Grype | 230 | 230 |
| 4 | `trivy.json` | Trivy Scan | 177 | 177 |
| 5 | `semgrep.json` | Semgrep JSON Report | 27 | 27 |
| 5 | `auth-report.json` → `auth-report.xml` | ZAP Scan | 13 | 13 |
| 6 | `checkov-terraform/results_json.json` | Checkov Scan | 80 | 80 |
| 6 | `kics-ansible/results.json` | KICS Scan | 10 | 10 |
| 6 | `kics-pulumi/results.json` | KICS Scan | 6 | 6 |
| 7 | `trivy-image.json` | Trivy Scan | 87 | 13 |
| 7 | `trivy-k8s.json` | **Trivy Scan** (not Trivy Operator Scan) | 174 | 86 |
| | | **total** | **804** | **642** |

Four of the nine did not import as the table in the lab says, and each failure is worth knowing:

- **Grype** — `HTTP 400 {"scan_date":["The scan_date cannot be in the future!"]}`. The JSON was regenerated tonight (`anchore/grype` v0.120.1 against the Lab 4 CycloneDX SBOM; only the `.txt` had been kept), and my machine was already on 12 Oct (MSK) while the server checks in UTC (11 Oct). Re-imported with the UTC date.
- **Semgrep** — `HTTP 400 'utf-8' codec can't decode byte 0x97`. Lab 5's `semgrep.json` was written through a PowerShell redirect in Windows-1252 (0x97 is an em dash). Re-encoded to UTF-8 (`labs/lab10/work/converted/semgrep.json`), all 27 results intact.
- **ZAP** — `HTTP 400 Internal error: Wrong file format, please use xml.` In 2.58.3 the `ZAP Scan` parser opens the file with `ElementTree` and rejects anything not ending in `.xml`, so the lab's `auth-report.json` cannot work. ZAP's "traditional" JSON is a 1:1 rendering of its traditional XML (`site/alerts/alertitem/instances/instance`), so I converted it element-for-element; 13 alerts, same as the JSON.
- **trivy-k8s** — imported fine as `Trivy Operator Scan` with **0 findings** (a silent failure; the importer's status check passes). `trivy k8s --format json` produces `{"ClusterName", "Resources": [...]}`, which is what the plain **Trivy Scan** parser reads (`dojo/tools/trivy/parser.py` handles `ClusterName`/`Resources`); the Operator parser expects Trivy-Operator CRDs. Deleted the empty test and re-imported as Trivy Scan → 174.

(Tests 2 and 3 are the empty shells the failed Semgrep/ZAP attempts left behind; they hold 0 findings.)

### 10.5 What is there

```
$ curl …/api/v2/tests/ | jq -r '.results[] | "\(.id)\t\(.scan_type)"'
1   Trivy Scan            (Lab 4 trivy.json)
2   Semgrep JSON Report   (empty, failed first attempt)
3   ZAP Scan              (empty, failed first attempt)
4   Checkov Scan
5   KICS Scan             (ansible)
6   KICS Scan             (pulumi)
7   Trivy Scan            (Lab 7 trivy-image.json)
9   Anchore Grype
10  Semgrep JSON Report
11  ZAP Scan
12  Trivy Scan            (Lab 7 trivy-k8s.json)

$ curl …/api/v2/findings/?active=true&limit=1000 | jq -c '[.results[].severity] | group_by(.) | map({severity: .[0], count: length})'
[{"severity":"Critical","count":40},{"severity":"High","count":284},{"severity":"Info","count":13},{"severity":"Low","count":53},{"severity":"Medium","count":252}]

$ curl …/api/v2/findings/?limit=1000 | jq -c '[.results[].title] | group_by(.) | map(select(length > 1) | {title: .[0], n: length}) | .[:5]'
[{"title":"CVE-2015-9235 Jsonwebtoken 0.1.0","n":4},{"title":"CVE-2015-9235 Jsonwebtoken 0.4.0","n":4},{"title":"CVE-2016-1000223 JWS 0.2.6","n":4},{"title":"CVE-2017-18214 Moment 2.0.0","n":4},{"title":"CVE-2018-16487 Lodash 2.4.2","n":4}]
```

**Active findings: Critical 40, High 284, Medium 252, Low 53, Info 13 — total 642** (804 imported, 162 marked duplicate).

118 titles occur more than once. Two of them, judged:

**1. `CVE-2015-9235 Jsonwebtoken 0.1.0` × 4 — one issue counted (at least) four times.** All four have the same package, version and path (`juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json`) in the same image: Lab 4 Trivy (#82), Lab 7 image scan (#304), and the Lab 7 cluster scan twice (#661, #748 — the `juice-shop` and `juice-plain` namespaces run the same image). DefectDojo got half of it right: #304 is marked duplicate of #82 and #748 duplicate of #661, because they have identical `hash_code`s (`878f89d0…` and `8921b787…`). But #661 is *not* a duplicate of #82 — the k8s flavour of the Trivy parser includes the workload in the hash — and Grype reports the same vulnerability under a different title, `GHSA-c7hr-j4mj-j2w6 in jsonwebtoken:0.1.0`, whose `vulnerability_ids` contain `CVE-2015-9235`. So it is **one fix (bump `express-jwt`'s jsonwebtoken to ≥ 4.2.2) that still shows as 3 active findings**. I decided by comparing component + version + file path + advisory aliases, not the title.

**2. `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` × 6 — six separate findings, and only two of them real.** Every one has a different file and line: `routes/search.ts:23`, `routes/login.ts:34`, and four under `data/static/codefixes/` (`dbSchemaChallenge_1.ts:5`, `dbSchemaChallenge_3.ts:11`, `unionSqlInjectionChallenge_1.ts:6`, `unionSqlInjectionChallenge_3.ts:10`). Same rule, different code, so not duplicates — they would need separate fixes. But the `codefixes` files are Juice Shop's coding-challenge answer snippets, served as text and never executed; those four are true matches of the pattern and false positives for the product. I decided by opening the paths and checking whether the file is reachable code (`routes/*` is mounted by `server.ts`; `codefixes/*` is only read as text). The two real ones are confirmed independently by ZAP (below).

### Which labs mattered this week

**Lab 5 matters most**: ZAP's `SQL Injection` (High, CWE-89) has two instances — `GET /rest/products/search?q='(` and `POST /rest/user/login` (`email='`) — and Semgrep points at exactly those two handlers (`routes/search.ts:23`, `routes/login.ts:34`), so a SAST hit and a DAST exploit agree on file, line and endpoint; add the hard-coded JWT secret in `lib/insecurity.ts:56` and that is this week's work. **Labs 4/7 contribute a short, fixable list** inside a lot of volume: of 506 active SCA findings only 241 are distinct package/version/advisory issues across 48 packages, and the criticals with a fix version (jsonwebtoken → 4.2.2, lodash → 4.17.12 with EPSS 0.21, crypto-js → 4.2.0, tar → 7.5.19) are a dependency bump each; **Lab 6's KICS secrets** (passwords in the Ansible inventory and Pulumi stack) need rotating regardless of whether that code is deployed. **Noise:** the Lab 7 cluster scan (86 "active" findings, 76 of them the same image CVEs again under a different hash), Grype-vs-Trivy double counting, the four `codefixes` SQLi hits, ZAP's Info items, and Checkov's 80 mediums on the intentionally vulnerable Lab 6 Terraform, which describes infrastructure this product does not run.

## Task 2

### 10.6 SLA

```
$ curl …/api/v2/sla_configurations/ | jq -r '.results[] | "\(.name): critical=\(.critical) high=\(.high) medium=\(.medium) low=\(.low)"'
Default: critical=7 high=30 medium=90 low=120            # before
$ PATCH /api/v2/sla_configurations/1/ {"critical":3,"high":14,"medium":60,"low":180}
Default: critical=3 high=14 medium=60 low=180            # after
No SLA Enforced: critical=7 high=30 medium=90 low=120
```

| Severity | Default | Mine | Why |
|---|---:|---:|---|
| Critical | 7 | **3** | This is an internet-facing app, and every Critical here that has a fix is either a dependency bump (jsonwebtoken, lodash, crypto-js, tar) or a base-image rebuild (libc6, libssl3t64) that CI can ship in a day; for well-known, old advisories like CVE-2015-9235 a week is longer than an attacker needs. |
| High | 30 | **14** | One two-week sprint: a High should be in the sprint after it is found, not "this month"; 30 days lets it slip across two planning cycles. |
| Medium | 90 | **60** | Two monthly releases; most Mediums are config/header issues (CSP, clickjacking, directory listing) that are cheap but need a release. |
| Low | 120 | **180** | Lows are mainly Debian base-image packages fixed by the routine base-image rebuild; a tight Low SLA produces breaches nobody acts on and teaches people to ignore the dashboard. |

### Active findings by severity and source tool

| Source (test) | Critical | High | Medium | Low | Info | Total |
|---|---:|---:|---:|---:|---:|---:|
| Lab 4 — Anchore Grype | 18 | 105 | 82 | 18 | 7 | 230 |
| Lab 4 — Trivy (image) | 10 | 66 | 70 | 31 | 0 | 177 |
| Lab 5 — Semgrep | 0 | 13 | 14 | 0 | 0 | 27 |
| Lab 5 — ZAP | 0 | 2 | 4 | 3 | 4 | 13 |
| Lab 6 — Checkov | 0 | 0 | 80 | 0 | 0 | 80 |
| Lab 6 — KICS (ansible + pulumi) | 0 | 11 | 2 | 1 | 2 | 16 |
| Lab 7 — Trivy (image, re-scan) | 1 | 12 | 0 | 0 | 0 | 13 |
| Lab 7 — Trivy (k8s) | 11 | 75 | 0 | 0 | 0 | 86 |
| **Total** | **40** | **284** | **252** | **53** | **13** | **642** |

The Lab 7 image re-scan is the useful kind of duplicate: 74 of its 87 findings collapsed onto Lab 4's scan of the same image, and 10 of the 13 that stayed active are CVEs that were not in the 21 Sep report at all — same bytes, new knowledge two weeks later.

### Age and SLA

All over the 642 active findings in the `/findings/` dump (`age` and `sla_days_remaining` are DefectDojo's own fields, computed from `date` = the `scan_date` I imported with):

| Metric | Value | How |
|---|---|---|
| Median age | **7 days** | `jq '[.results[] \| select(.active) \| .age] \| sort \| (.[length/2\|floor] + .[(length-1)/2\|floor]) / 2'` (Python `statistics.median` gives the same) |
| Oldest active finding | **20 days** — the Lab 4 Trivy scan of 2026-09-21 (e.g. #1 `CVE-2026-18374 Libc6 2.41-12+deb13u2`) | `jq '[.results[] \| select(.active) \| .age] \| max'` |
| Inside SLA | **86.0 %** (541 / 629) | `jq '[.results[] \| select(.active and .sla_days_remaining != null)] \| (map(select(.sla_days_remaining >= 0)) \| length) / length'` — the 13 Info findings have no SLA and are left out; with them in the denominator it is 84.3 % |

The 88 breaches are **22 Criticals** (everything Critical older than 3 days) and **66 Highs** (all from the 21 Sep Trivy scan). Under the stock 7/30/90/120 the same data shows **98.4 %** inside SLA (only 10 Criticals overdue): the default made the project look healthy because nothing here is older than 20 days, not because anything was fixed.

### What Labs 8 and 9 add that these numbers do not

Lab 8's signature and attestation results (including the `cosign verify` that correctly failed on the tampered digest: `Error: no signatures found`) and Lab 9's Falco alerts (shell in container, `/tmp` writes, the CRITICAL mining connection) have no DefectDojo parser, so the 642 contains no supply-chain or runtime evidence at all. I would send Falco alerts through Falcosidekick's DefectDojo output and record failed `cosign verify` runs in CI as findings through the **Generic Findings Import**, so a runtime detection or an unsigned image gets an owner and a deadline like any CVE.

### Risk acceptance

**`GHSA-5mrr-rgp6-x4gr` — Command Injection in `marsdb` 0.6.11 (Critical)**, active as #100 (Trivy), #587 (Grype), #673 (Trivy k8s); #316/#760 already collapsed as duplicates.

- **Why accept rather than fix:** every version of `marsdb` is affected and there is no fixed release (`fix_version` is empty in all five findings); the package is abandoned. Juice Shop uses it on purpose for its NoSQL-injection challenges, so removing it is a code change, not a bump.
- **Expiry: 2026-12-15** (end of this engagement). By then: replace `marsdb` with a maintained in-memory store, or re-accept with a new owner and date.
- **Compensating controls, already in place from earlier labs:** the Lab 7 deployment runs as non-root with `readOnlyRootFilesystem`, all capabilities dropped and `allowPrivilegeEscalation: false`, under PSS `restricted` and a NetworkPolicy, which caps what a successful command injection can do; the Lab 9 Falco rules (`Terminal shell in container`, `Write Below Tmp In Container`, the CRITICAL miner rule) alert on the post-exploitation steps. Owner: me. Review: weekly SLA report.

### Executive summary

Juice Shop has 642 open findings, but after removing the same issue reported by several scanners they come down to about 377 distinct problems (241 dependency issues across 48 packages plus 136 code/config findings), 86 % of them inside the new deadlines. The single biggest risk is SQL injection on the public search and login endpoints, confirmed by both the code scanner and a live attack test (`routes/search.ts:23`, `routes/login.ts:34`), together with 18 critical dependency vulnerabilities, most of which are one version bump each. To close it I need one sprint from the app team to parameterise those two queries and bump jsonwebtoken, lodash, crypto-js and tar, plus approval to run DefectDojo imports from CI on every build so these numbers stay current instead of being a one-off snapshot.

## Bonus

Walkthrough: [`submissions/lab10-walkthrough.md`](lab10-walkthrough.md).

The hardest part to explain concisely was not any one tool but why the numbers change from tool to tool: why 804 imported findings are 642 "active" and ~377 real problems, why the same image scanned twice has 13 new CVEs, and why Falco on my laptop needed a different version than the lab. Each of those needs a sentence of context the dashboard does not carry. It tells me that for the next project I would write down the *unit* first — what one finding means (package+version+advisory for SCA, file+line for SAST, endpoint+parameter for DAST) — and record every deviation from the plan (a version swap, a converted file, a parser that silently returned 0) at the moment it happens, because reconstructing them later is where the time went.
