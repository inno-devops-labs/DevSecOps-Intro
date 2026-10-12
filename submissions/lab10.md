# Lab 10 — Vulnerability Management: The Capstone

**Environment**
- Host: Windows 11, Docker Desktop 29.7.2 (4 GiB VM), Git Bash, `jq 1.8.2`.
- DefectDojo **2.58.3** (`release` profile), confirmed by `GET /api/v2/oa3/schema/` (`info.version: 2.58.3`) and by `dojo.__version__` inside `uwsgi`.
- Inputs: the reports from Labs 4–7, all still on disk.

**What I had to do differently from the lab text.** Each change was needed to get a correct result, and each is shown below:
1. **I pinned the images, not just the clone.** `docker-compose.yml` uses `defectdojo/defectdojo-django:${DJANGO_VERSION:-latest}`, nothing in the 2.58.3 clone sets that variable, and on Docker Hub `latest` is the same digest as `3.4.0` (`sha256:b7d5e1de…`). Running `docker compose up -d` as written would have started DefectDojo 3.x from a 2.58.3 checkout. I started it with `DJANGO_VERSION=2.58.3 NGINX_VERSION=2.58.3`.
2. **ZAP:** the importer fails (`HTTP 400 … Wrong file format, please use xml.`). DefectDojo 2.58.3's ZAP parser accepts only `.xml` (`dojo/tools/zap/parser.py:76`), but Lab 5's `zap-auth.yaml` writes `traditional-json`. I converted the JSON to ZAP's `traditional-xml` layout with a 40-line script. It maps every field one-to-one (13 alerts and 43 instances in, 13 and 43 out) and invents nothing. I did not re-run the 25-minute scan, which would have produced a *different* set of alerts.
3. **`trivy-k8s.json`:** imported with the lab's `Trivy Operator Scan` parser it gives **0 findings**. That parser reads Trivy Operator CRDs. DefectDojo's regular **`Trivy Scan`** parser reads the `trivy k8s` format explicitly (`ClusterName` and `Resources`, `dojo/tools/trivy/parser.py:176,216`), and with it the file gives 174.
4. **Deduplication was off** (`enable_deduplication: false`). The goal is to "make the duplicates collapse", so I enabled it and ran `manage.py dedupe --dedupe_sync`.
5. **Finding dates.** Every finding was dated the import day (2026-10-12, `age: 0`), which makes every age and SLA number meaningless. I set each finding's `date` to the day its scan actually ran, taken from the report file timestamps (Lab 4: 2026-09-20; Labs 5–6: 2026-09-27; Lab 7: 2026-10-04). I did this through the model's own `save()`, so DefectDojo recomputed `sla_expiration_date` itself.

## Task 1

### Imports (10.4)

`bash labs/lab10/imports/run-imports.sh`, plus the two follow-up imports described above.

| Lab | File | Parser | Test | Findings |
|---|---|---|---|---|
| 4 | `labs/lab4/grype-from-sbom.json` | `Anchore Grype` | 1 | 183 |
| 4 | `labs/lab4/trivy.json` | `Trivy Scan` | 2 | 177 |
| 5 | `labs/lab5/results/semgrep.json` | `Semgrep JSON Report` | 3 | 27 |
| 5 | `labs/lab5/results/auth-report.json` | `ZAP Scan` | 4 | **failed**: JSON not accepted |
| 5 | `auth-report.xml` (converted from the JSON) | `ZAP Scan` | 10 | 13 |
| 6 | `labs/lab6/results/checkov-terraform/results_json.json` | `Checkov Scan` | 5 | 80 |
| 6 | `labs/lab6/results/kics-ansible/results.json` | `KICS Scan` | 6 | 10 |
| 6 | `labs/lab6/results/kics-pulumi/results.json` | `KICS Scan` | 7 | 6 |
| 7 | `labs/lab7/results/trivy-image.json` | `Trivy Scan` | 8 | 87 |
| 7 | `labs/lab7/results/trivy-k8s.json` | `Trivy Operator Scan` | 9 | **0**: wrong parser for this format |
| 7 | `labs/lab7/results/trivy-k8s.json` | `Trivy Scan` | 11 | 174 |

The counts match the source tools:
- **Checkov:** 80 = 78 terraform + 2 secrets.
- **Trivy, Lab 7 image:** 87 = 85 HIGH/CRITICAL + 2 secrets.
- **Trivy, Lab 7 k8s:** 174 = 22 + 148 + 4 secrets. These are doubled because the hardened Deployment runs the same image as its initContainer.
- **ZAP:** 13 alerts.

Tests 4 and 9 are empty, and I kept them as a record of the two failures.

### What is in it (10.5)

```bash
curl … "$DD_URL/api/v2/findings/?active=true&limit=1000" | jq -c '[.results[].severity] | group_by(.) | map({severity: .[0], count: length})'
```

| Active findings | Critical | High | Medium | Low | Info | **Total** |
|---|---|---|---|---|---|---|
| As imported | 57 | 405 | 235 | 47 | 13 | **757** |
| After `dedupe` (162 marked duplicate) | 36 | 264 | 235 | 47 | 13 | **595** |
| After the risk acceptance in Task 2 | 33 | 264 | 235 | 47 | 13 | **592** |

**Duplicate titles.** 118 titles appear more than once, and together they cover 427 of the 757 findings. Two of them, judged by looking at `test`, `component_name@version`, `file_path:line` and DefectDojo's own `hash_code`:

1. **`CVE-2015-9235 Jsonwebtoken 0.1.0`, ×4: one issue counted four times.**
   - All four point at the same file in the same image, `juice-shop/node_modules/express-jwt/node_modules/jsonwebtoken/package.json`.
   - Test 2 (Lab 4) and test 8 (Lab 7) are two scans of the identical digest `fd58bdc9…`.
   - Test 11 holds it twice, once for the main container and once for the initContainer.
   - DefectDojo half agrees: tests 2 and 8 share `hash_code 878f89d0…`, and the two test-11 rows share `8921b787…`. `dedupe` collapsed it from 4 to 2, but not to 1, because the k8s variant hashes differently.
   - The Grype copy (`GHSA-c7hr-j4mj-j2w6 in jsonwebtoken:0.1.0`, test 1) is the same issue again under a different title, so no title-based or hash-based dedupe sees it.
2. **`…express-sequelize-injection`, ×6: six separate findings.**
   - All six are in the Semgrep test, at six different `file:line` locations with six different hashes.
   - Two are real code: `routes/search.ts:23` and `routes/login.ts:34`, the SQL injection ZAP confirmed in Lab 5.
   - Four are in `data/static/codefixes/*.ts`, deliberately vulnerable teaching snippets that ship but never run.
   - Each real one needs its own fix, so collapsing them would hide work.

Deduplication can also go wrong the other way. `CVE-2026-93748 HTTP-Cache-Semantics 4.2.0` sits in **two** install paths, `make-fetch-happen/node_modules/…` and `sqlite3/node_modules/…`. Within one test DefectDojo gave both the same hash and kept one, but they are two copies with two different parent packages to bump.

**Which labs earned action this week, and which were noise.**
- **Lab 5 contributed the only finding I would stop work for:** an unauthenticated SQL injection that two independent tools reached from opposite sides. That was the ZAP High on `/rest/products/search` and Semgrep's sink at `search.ts:23`, and I reproduced it with one request.
- **Labs 4 and 7 contributed the second tier:** 33 Critical findings, almost all with a published fix (jsonwebtoken, lodash, crypto-js, tar, libssl). They are cheap to close but inflated about four-fold, because the *same image* was scanned four times (Grype, Trivy twice, `trivy k8s`).
- **Lab 6 contributed mostly noise *for this product*.** Its 80 Checkov findings all arrive as **Medium**, only because open-source Checkov reports no severity and DefectDojo picks a default. They describe sample Terraform that Juice Shop is not deployed with. KICS's 10 Ansible findings are hardcoded passwords in sample playbooks.
- **Labs 1–3, 8 and 9 contributed nothing countable**, which is not the same as nothing useful (Task 2).

## Task 2

### SLA (10.6)

```bash
curl -X PATCH "$DD_URL/api/v2/sla_configurations/1/" … -d '{"critical":3,"high":21,"medium":90,"low":180}'
# Default: critical=3 high=21 medium=90 low=180
```

| Severity | Default | Mine | Why |
|---|---|---|---|
| Critical | 7 | **3** | Every Critical here is either an internet-reachable injection or a library with a published fix. Both are a dependency bump or a two-line patch through a pipeline that already builds and scans in minutes. Three calendar days covers a weekend; a week gives attackers a weekend *and* a week. |
| High | 30 | **21** | One two-week sprint plus a week of slack. With 264 Highs, 30 days lets them drift into a second month without anyone deciding to defer them. |
| Medium | 90 | **90** (unchanged) | Most Mediums are IaC and header hygiene, with severity *assigned by default* (Checkov). A quarterly hardening cycle fits them, and tightening would only move noise up the queue. |
| Low | 120 | **180** | Lows here are hygiene (timestamps, headers, unpinned package versions). Twice-yearly review is honest; a 120-day deadline nobody meets teaches the team to ignore deadlines. |

### Numbers (10.7)

**Active findings by severity and by source tool**, after `dedupe` and the risk acceptance:

| Tool (test) | Crit | High | Med | Low | Info | Total |
|---|---|---|---|---|---|---|
| Anchore Grype, Lab 4 SBOM (1) | 13 | 85 | 65 | 12 | 7 | 182 |
| Trivy Scan, Lab 4 image (2) | 9 | 66 | 70 | 31 | 0 | 176 |
| Semgrep JSON Report, Lab 5 (3) | 0 | 13 | 14 | 0 | 0 | 27 |
| ZAP Scan, Lab 5 (10) | 0 | 2 | 4 | 3 | 4 | 13 |
| Checkov Scan, Lab 6 (5) | 0 | 0 | 80 | 0 | 0 | 80 |
| KICS Scan, Lab 6 Ansible (6) | 0 | 9 | 0 | 1 | 0 | 10 |
| KICS Scan, Lab 6 Pulumi (7) | 0 | 2 | 2 | 0 | 2 | 6 |
| Trivy Scan, Lab 7 image (8) | 1 | 12 | 0 | 0 | 0 | 13 |
| Trivy Scan, Lab 7 trivy-k8s (11) | 10 | 75 | 0 | 0 | 0 | 85 |
| **Total** | **33** | **264** | **235** | **47** | **13** | **592** |

The three numbers, computed from `GET /api/v2/findings/?active=true&limit=1000`. DefectDojo's `age` field is `today − date`, and `date` is the day each scan ran (see change 5 above).

| Metric | Value | Method |
|---|---|---|
| Median age of active findings | **22 days** | `statistics.median([f["age"] for f in results])`. The ages are 22 days (358 findings, Lab 4), 15 (136, Labs 5–6) and 8 (98, Lab 7). |
| Oldest active finding | **22 days** | `max(f["age"])`. These are Lab 4's findings, first seen on 2026-09-20. |
| Share inside SLA | **68.2 %** (395 / 579) | Count of `sla_expiration_date >= 2026-10-12` over findings that have an SLA. The 13 Info findings have no SLA (`sla_expiration_date: null`) and are excluded. |

By severity:
- **Critical:** 0 of 33 inside SLA.
- **High:** 113 of 264.
- **Medium and Low:** all inside.

Under the **default** SLA, the same data is 94.3 % compliant, with every High "inside". The difference is the point of choosing numbers: the defaults would report a healthy program while 151 Highs sit unfixed for three weeks.

The "one number" also needs reading.
- The 33 active Critical findings are **14 distinct (CVE, package, version) issues**, once Grype's CVE+GHSA pairs are matched to Trivy's CVE-only ones.
- Those come down to about **6 changes**: bump `jsonwebtoken`, `lodash`, `crypto-js` and `tar`; rebase the image for `libssl3t64` and `libc6`; replace `decompress`, which has no fix.

**What Labs 8 and 9 produced that none of this includes.** None of these numbers include Lab 8's signatures and SBOM/provenance attestations (evidence that an artifact is what we built), or Lab 9's Falco detections and Conftest policy results. DefectDojo has no parser for either, and they are controls and events, not vulnerabilities. I would track them next to it as two coverage metrics: the share of deployed digests with a valid signature *and* SBOM attestation, and the share of manifests passing Conftest in CI. I would also feed Conftest failures into DefectDojo through its Generic Findings Import, so policy violations get owners and SLAs too.

### Risk acceptance

**Risk acceptance #1** was created through `POST /api/v2/risk_acceptance/`.

| | |
|---|---|
| **Findings** | 180, 283, 626: `GHSA-5mrr-rgp6-x4gr`, command injection in **`marsdb 0.6.11`**, Critical, the same issue as reported by Grype, Trivy and `trivy k8s` |
| **Why accept** | There is no fixed version: `marsdb` has been unmaintained since 2016. The remediation is to replace it, which is a design change, not this sprint. |
| **Expiry** | **2027-01-12** (90 days), with `reactivate_expired: true`, so the findings come back on their own. |
| **Compensating controls** | From Lab 7: the pod runs as UID 65532 with all capabilities dropped and seccomp `RuntimeDefault`; `readOnlyRootFilesystem` (writes go only to six size-limited emptyDirs); a NetworkPolicy with default deny and DNS-only egress, so an injected command cannot call out; no service-account token. |
| **Trigger to revisit early** | A fixed version appears, the advisory joins CISA KEV, or its EPSS rises above 0.1. |

### Executive summary

Juice Shop has 592 active findings, which reduce to 14 distinct critical vulnerabilities closable with about six changes, and 68 % of findings are inside the deadlines we set. Every Critical is already past its 3-day SLA. The single biggest risk is the unauthenticated SQL injection in product search and login, confirmed independently by DAST and SAST, which exposes the user table including password hashes. Closing it takes one developer for one sprint: parameterise two queries, apply the four dependency bumps and the base-image update, and name an owner for replacing `marsdb` before its risk acceptance expires on 2027-01-12.

## Bonus

The walkthrough is in [`submissions/lab10-walkthrough.md`](lab10-walkthrough.md), about 700 words.

**What was hardest to explain concisely** were the places where a tool's output and the truth disagreed:
- Cosign's `--tlog-upload=false` still uploading to public Rekor (Lab 8);
- DefectDojo's `latest` tag silently being 3.x;
- Trivy Operator's parser "succeeding" with zero findings;
- a ZAP report DefectDojo would not read.

Each takes one sentence to state and a paragraph to make believable, because the reader's default assumption is that the tool did what it said. That tells me how I would document the next project. Record, at the moment it happens, *what I expected, what the tool actually did, and the one command that proved the difference*. Reconstructing that chain weeks later is what took the words.

## Clean-up

`docker compose down -v` from `labs/lab10/work/dd` after the run. Nothing under `labs/lab10/work/` and none of the importer's `import-*.json` responses are committed.
