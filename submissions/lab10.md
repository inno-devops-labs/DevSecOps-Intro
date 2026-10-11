# Lab 10 — Vulnerability Management: The Capstone

## Task 1

### 1. DefectDojo version

**DefectDojo 2.58.3.** I had to pin it twice. Cloning the `2.58.3` tag pins only the compose file. `docker-compose.yml` still references `defectdojo/defectdojo-django:${DJANGO_VERSION:-latest}`, and on the first `docker compose up` the stack came up on the `latest` images:

```
$ docker compose exec -T uwsgi python -c "import dojo; print(dojo.__version__)"
3.4.0
```

That is the 3.x parser naming the lab warns about, coming in through the image tag rather than the clone. That instance was still empty, and its database had already been migrated by 3.4, so I removed it with `docker compose down -v` and started again with the images pinned as well:

```
$ export DJANGO_VERSION=2.58.3 NGINX_VERSION=2.58.3
$ docker compose up -d
$ docker compose exec -T uwsgi python -c "import dojo; print(dojo.__version__)"
2.58.3
```

The `release` profile was used. The API token came from `POST /api/v2/api-token-auth/`. Product type 1 was `Research and Development`, and the importer created product 1, `OWASP Juice Shop`, and engagement 1, `Course Semester Run`.

### 2. Imports: parser and finding count per file

`bash labs/lab10/imports/run-imports.sh` imported 7 of 9 files on the first run and failed two. The final table:

| Lab | File | Parser | Findings imported |
| --- | ---- | ------ | ----------------: |
| 4 | `labs/lab4/grype-from-sbom.json` | `Anchore Grype` | 230 |
| 4 | `labs/lab4/trivy.json` | `Trivy Scan` | 225 |
| 5 | `labs/lab5/results/semgrep.json` | `Semgrep JSON Report` | 27 |
| 5 | `labs/lab5/results/auth-report.json` (converted to ZAP XML) | `ZAP Scan` | 13 |
| 6 | `labs/lab6/results/checkov-terraform/results_json.json` | `Checkov Scan` | 80 |
| 6 | `labs/lab6/results/kics-ansible/results.json` | `KICS Scan` | 10 |
| 6 | `labs/lab6/results/kics-pulumi/results.json` | `KICS Scan` | 6 |
| 7 | `labs/lab7/results/trivy-image.json` | `Trivy Scan` | 87 |
| 7 | `labs/lab7/results/trivy-k8s.json` | `Trivy Scan` (not `Trivy Operator Scan`) | 174 |
| | | **Total** | **852** |

Notes on the table:

- **Lab 4 reports were regenerated.** `grype-from-sbom.json` and `trivy.json` were no longer on disk. I regenerated them with Lab 4's own commands against the same SBOM and image digest. With today's databases Grype now reports 231 matches, against 182 in Lab 4. The image is the same, but the vulnerability DB has grown since. The Grype parser merged one of the 231 matches, which leaves 230.
- **The Trivy counts include secrets.** 225 is 221 vulnerabilities plus 4 secret findings, and 87 is 85 plus 2. The parser also imports Trivy's secret results, here the RSA private key in `lib/insecurity.ts` / `build/lib/insecurity.js`.
- **ZAP failed as JSON.** The import was rejected with `HTTP 400 … 'Internal error: Wrong file format, please use xml.'`, because the 2.58.3 `ZAP Scan` parser reads only ZAP's traditional XML report. Rather than re-scan, which would give different data, I converted Lab 5's saved JSON report into the same XML schema (`OWASPZAPReport/site/alerts/alertitem/instances/instance`, mapping fields 1:1). The converted file has 13 alert items and 43 instances, the same as the Lab 5 report. The import then succeeded with 13 findings.
- **`trivy-k8s.json` imported as `Trivy Operator Scan` gives 0 findings.** It returned HTTP 201 and an empty test. That file comes from the `trivy k8s` CLI (top-level `ClusterName` + `Resources`). In 2.58.3, `dojo/tools/trivy_operator/parser.py` only reads Trivy Operator CRD exports (`vulnerabilityreports.aquasecurity.github.io`, …), while `dojo/tools/trivy/parser.py` explicitly handles `ClusterName`/`Resources`. Re-imported as `Trivy Scan` it gives 174. I deleted the empty failed tests (the 400 ZAP attempt and the 0-finding Operator attempt) so they don't show up as "scanned, clean".

### 3. Active findings by severity

Straight after import, with the stock setting `enable_deduplication: false`, all 852 were active:

```
$ curl … "/api/v2/findings/?active=true&limit=1000" | jq -c '[.results[].severity] | group_by(.) | map({severity: .[0], count: length})'
[{"severity":"Critical","count":65},{"severity":"High","count":435},{"severity":"Info","count":13},{"severity":"Low","count":56},{"severity":"Medium","count":283}]
```

I then made the duplicates collapse: `PATCH /api/v2/system_settings/1/ {"enable_deduplication": true}`, followed by `docker compose exec uwsgi python manage.py dedupe --dedupe_sync` (`Completed batch deduplication for 852 findings across 9 tests`). 174 findings were marked `duplicate`. Before the risk acceptance in Task 2, this left:

| Severity | Active (no dedupe) | Active (after dedupe) |
| -------- | -----------------: | --------------------: |
| Critical | 65 | 44 |
| High | 435 | 282 |
| Medium | 283 | 283 |
| Low | 56 | 56 |
| Info | 13 | 13 |
| **Total** | **852** | **678** |

Where the 174 duplicates came from: 85 of the 87 Lab 7 image findings matched the Lab 4 Trivy scan of the same image, and 88 of the 174 `trivy k8s` findings matched other rows *inside the same test*. Lab 7's Bonus initContainer `seed` runs the same image as the app container, so every CVE was reported twice (the "doubling" Lab 7 explained). The last one is covered in the next section.

### 4. Two titles that appear more than once

`[.results[].title] | group_by(.) | map(select(length > 1))` finds 118 repeated titles.

**`CVE-2015-9235 Jsonwebtoken 0.1.0` (n = 4): one issue counted four times.** The four rows are tests 2 (Trivy, Lab 4), 8 (Trivy, Lab 7 image) and 11 (Trivy k8s, twice). All four have the same CVE, the same package version and the same `file_path` (`juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json`) in the same image digest. Tests 2 and 8 also have the same `hash_code` (`878f89d0598d…`), so after dedupe the test 8 row is a duplicate of test 2. The two test 11 rows have a different hash (`8921b78764fd…`) because the Kubernetes resource is part of it. They are the app container and the `seed` initContainer, so one of them collapsed into the other, but neither collapsed into the image scans. Grype reports the same flaw as `GHSA-c7hr-j4mj-j2w6 in jsonwebtoken:0.1.0` (alias `CVE-2015-9235`). It is a different title and hash, so it never matches at all. The truth is one vulnerable file in one image. DefectDojo still shows it as **3 active rows** (Grype, Trivy L4, Trivy k8s).

**`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` (n = 6): six separate findings, of which two are real.** Every row has a different `file_path:line` and a different `hash_code`: `routes/login.ts:34`, `routes/search.ts:23` and four in `data/static/codefixes/` (`dbSchemaChallenge_1.ts:5`, `_3.ts:11`, `unionSqlInjectionChallenge_1.ts:6`, `_3.ts:10`). They are separate code locations, so deduplication correctly leaves all six. Triage is a different question: Lab 5 showed the four `codefixes/` files are deliberately vulnerable teaching snippets that are never routed. They should be closed as out of scope, not merged.

How I decided: a repeated title means "same issue" only if the **same flaw sits in the same artifact at the same location**. So I compared `vulnerability_ids` (CVE/GHSA aliases), `component_name@version`, `file_path:line` and the image the scan targeted, and I used `hash_code` to see what DefectDojo itself thinks. The hash is not always right, in either direction. The two `http-cache-semantics@4.2.0` copies under `make-fetch-happen/node_modules/` and `sqlite3/node_modules/` share a `hash_code` because the Trivy hash leaves out the path. Dedupe merged them, although they are two installs that need two upgrades.

Counting the way I described, by CVE alias + component + version across the four SCA tests, the 542 active SCA rows are **239 unique vulnerabilities**: 134 found by Grype and Trivy L4, 79 by Grype, Trivy L4 and Trivy k8s, 15 by Grype only, 4 by Trivy L4 only, 5 by Trivy L4 and Trivy k8s, and 2 by all four. With the 136 non-SCA findings, the project has **about 375 distinct issues behind the 852 rows**.

### 5. Which labs mattered this week, and which were noise

**Act this week:**
- **Lab 5.** The SQL injection in `routes/login.ts:34` and `routes/search.ts:23` was found by Semgrep and independently confirmed exploitable by ZAP (`POST /rest/user/login`, `GET /rest/products/search`). It is the only finding in the system with two tools and a working request behind it.
- **Lab 4/7 SCA.** The 15 unique Critical SCA vulnerabilities that have a fix (of 16 still active: `jsonwebtoken`, `crypto-js`, `lodash`, `tar`, `handlebars`, `proxy-addr`, OpenSSL and glibc; only `marsdb` has none), because each one is a dependency bump and Lab 7 showed eight of the top ten are only five upgrades.

**Mostly noise in this number:**
- **Lab 6.** Its 96 findings (80 Checkov + 16 KICS) are real, but they come from the deliberately broken sample IaC in `labs/lab6/vulnerable-iac/`, which doesn't deploy Juice Shop. They belong to another "product". Inside this product they only inflate the count.
- **Lab 7's `trivy k8s` run.** About 84 of its active rows re-report, under a different hash, the same image vulnerabilities Lab 4 already had.
- **Grype vs Trivy.** Most of the SCA total is the same CVE counted once per tool.

So the single "667" mixes one confirmed exploitable bug class, about 239 dependency CVEs and about 100 findings in code that isn't this application.

## Task 2

### 1. SLA: mine against the defaults

```
$ curl … /api/v2/sla_configurations/ | jq -r '.results[] | "\(.name): critical=\(.critical) high=\(.high) medium=\(.medium) low=\(.low)"'
Default: critical=7 high=30 medium=90 low=120
```

I changed it with `PATCH /api/v2/sla_configurations/1/ {"critical":3,"high":14,"medium":60,"low":180}`, which now reads `Default: critical=3 high=14 medium=60 low=180`. DefectDojo recalculated every finding's `sla_expiration_date`: Critical → 2026-10-14, High → 2026-10-25, Medium → 2026-12-10, Low → 2027-04-09.

| Severity | Default | Mine | Why |
| -------- | ------: | ---: | --- |
| Critical | 7 | **3** | Juice Shop is an internet-facing web app, and the time from disclosure to exploitation for critical web and library bugs is now measured in days. Almost every Critical here is a dependency with a released fix, so the work is a version bump plus a CI run, which fits in 3 days. |
| High | 30 | **14** | One sprint. Highs here are mostly the same kind of upgrade, plus the confirmed SQL injection. 30 days would leave a confirmed injection open for a month. |
| Medium | 90 | **60** | Mediums are mostly hardening and header issues (ZAP) or IaC hygiene. 60 days is two release cycles, enough to batch them into planned work without letting them become permanent. |
| Low | 120 | **180** | I *raised* this one. Lows (missing headers, DS-0026 style) are cheap to ignore and expensive to chase. A shorter Low SLA mostly produces breached-SLA noise that hides the Criticals. 180 days ties them to the twice-yearly dependency refresh. |

### 2. Active findings by severity and by source tool

After dedupe and the risk acceptance below (`/api/v2/findings/?active=true` → `count: 667`):

| Source (test) | Critical | High | Medium | Low | Info | Total |
| ------------- | -------: | ---: | -----: | --: | ---: | ----: |
| Grype — Lab 4 SBOM (1) | 16 | 105 | 80 | 18 | 7 | 226 |
| Trivy image — Lab 4 (2) | 12 | 75 | 99 | 34 | 0 | 220 |
| Trivy image — Lab 7 (8) | 0 | 1 | 0 | 0 | 0 | 1 |
| Trivy k8s — Lab 7 (11) | 9 | 75 | 0 | 0 | 0 | 84 |
| Semgrep — Lab 5 (3) | 0 | 13 | 14 | 0 | 0 | 27 |
| ZAP authenticated — Lab 5 (10) | 0 | 2 | 4 | 3 | 4 | 13 |
| Checkov — Lab 6 (5) | 0 | 0 | 80 | 0 | 0 | 80 |
| KICS Ansible — Lab 6 (6) | 0 | 9 | 0 | 1 | 0 | 10 |
| KICS Pulumi — Lab 6 (7) | 0 | 2 | 2 | 0 | 2 | 6 |
| **Total** | **37** | **282** | **279** | **56** | **13** | **667** |

### 3. Age and SLA compliance

**As DefectDojo reports them:**

```
jq '[.results[].age] | sort | .[length/2|floor], max'                       -> median 0, max 0
jq '[.results[] | select(.sla_expiration_date)] | length,
    ([.[] | select(.sla_days_remaining >= 0)] | length)'                    -> 654 tracked, 654 inside
```

- Median age of active findings: **0 days**
- Oldest active finding: **0 days**
- Share inside SLA: **654 / 654 = 100%** (the 13 Info findings have no SLA)

These numbers are true and useless. DefectDojo sets a finding's `date` to the import date when no `scan_date` is sent, and `run-imports.sh` doesn't send one. So every finding "was found today".

**Dated by when the scan actually first found it.** I took the date of the scan that first produced each finding (the commit dates: Lab 4 on 2026-09-17, Labs 5 and 6 on 2026-09-24, Lab 7 on 2026-10-04) and computed against today, 2026-10-11, with my SLA:

```python
first = {1: "2026-09-17", 2: "2026-09-17", 3: "2026-09-24", 10: "2026-09-24", 5: "2026-09-24",
         6: "2026-09-24", 7: "2026-09-24", 8: "2026-10-04", 11: "2026-10-04"}
sla = {"Critical": 3, "High": 14, "Medium": 60, "Low": 180}
age = (date(2026, 10, 11) - date.fromisoformat(first[f["test"]])).days
inside = age <= sla[f["severity"]]
```

- Median age: **24 days**. Most active rows are the Lab 4 SCA findings.
- Oldest: **24 days**, for example `GHSA-c7hr-j4mj-j2w6 in jsonwebtoken:0.1.0`, first reported on 2026-09-17.
- Inside SLA: **411 / 654 = 62.8%**. **All 37 Criticals** and **206 Highs** are past due. Every Medium and Low is still inside its window.

The fix in the pipeline is to send `scan_date` with every import. Re-imports should use `reimport-scan` into the same test, not `import-scan`, so the original `date` survives and the age reflects the first sighting.

### 4. What Labs 8 and 9 produced that none of these numbers include

None of these numbers include the **controls** from Labs 8 and 9: the Cosign signature and SBOM attestation on the image digest, Falco's runtime alerts (`Write below tmp in container`, the Critical cryptominer rule) and the Conftest policy results. DefectDojo has no parser for any of them, so the dashboard shows only what is wrong and nothing that protects. I would turn the Conftest and Falco output into SARIF or Generic Findings Import JSON and import it as its own tests. That way a policy failure or a runtime alert is a finding with an owner and an SLA. I would also record "image digest verified by Cosign" as a product-level control in the engagement, not leave it in the CI log.

### 5. Risk acceptance

I created Risk Acceptance 1 via `POST /api/v2/risk_acceptance/` (`decision: A`, expiry **2027-01-09T00:00:00Z**, `reactivate_expired: true`) covering **11 findings**: the two Critical and two Medium advisories for **`decompress@4.2.1`**, as reported by Grype, Trivy L4, Trivy L7 and Trivy k8s. After that they show `active: false, risk_accepted: true`, and the active count dropped from 678 to 667 (7 Critical, 4 Medium).

- **Why accept it.** None of these advisories has a fixed release, so "upgrade" isn't available. I checked reachability inside the image. `decompress` isn't a direct dependency. Its only consumer is `download@8`, which Juice Shop calls only from `build/lib/utils.js` → `downloadToFile(url, dest)`, used at start-up to fetch customization images. That function never passes `extract: true`, so the vulnerable archive-extraction path is never executed.
- **Compensating controls.**
  - Lab 7's NetworkPolicy allows the pod no egress except DNS, so `downloadToFile` can't fetch an attacker-supplied archive even if the config were changed.
  - The customization URLs are set only in the image's own config.
  - `readOnlyRootFilesystem: true` limits any write to the declared emptyDir volumes.
- **Expiry and review.** It expires on 2027-01-09 (90 days), or earlier if `decompress` or `download` ships a fix. On expiry DefectDojo reactivates the findings. The recommendation recorded with the acceptance is to replace `download` with native `fetch` in `downloadToFile`, which removes the dependency entirely.

### 6. Executive summary

Juice Shop has **667 active findings**, but after removing tool double-counting they come down to about **375 distinct issues**. all 37 Critical rows (16 unique vulnerabilities) are past a 3-day SLA, and only 62.8% of findings are inside their deadlines. The single biggest risk is the **SQL injection in the login and search endpoints**, which two independent tools confirmed and which lets an anonymous user log in as admin. To close it I need **one developer for two days** to switch those two queries to parameterised `replacements` and re-run the ZAP scan. After that, a recurring half day per sprint to apply the upgrades behind the 15 fixable Criticals would bring them back inside SLA.

## Bonus

The walkthrough is in `submissions/lab10-walkthrough.md` (≈ 700 words, five minutes spoken).

The hardest part to explain concisely was everything between "the scanner said X" and "X is true". Lab 4's Grype/Trivy disagreement, Lab 6's IaC that isn't the product, the `trivy k8s` doubling and the `hash_code` that merges two installs all needed a paragraph each. The decisions themselves fit in one line. The findings were easy to describe. The provenance of each number was not: which scanner, which DB date, which parser and which dedupe rule produced it. For the next project I would document **provenance first**. Every number I report would carry the tool version, the DB or parser it came from and the date it was first seen, written down at the moment of the scan, so the report quotes it rather than reconstructing it weeks later from commit dates.
