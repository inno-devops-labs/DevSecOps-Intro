# Lab 10 — Vulnerability Management Capstone

Executed **2026-10-11**. DefectDojo **2.58.3**, source commit `ea611112772b08b74e6429e833728ce500b4c284`, with both `defectdojo-django:2.58.3` and `defectdojo-nginx:2.58.3` explicitly pinned. Docker Compose project: `lab10`. Both tasks and the walkthrough bonus were completed. The UI is bound only to **127.0.0.1:8080**; the database has no published host port.

The retained Lab 4–7 JSON reports are the evidence inputs, not regenerated or illustrative findings. Credentials, bulk API responses, the cloned application and execution logs remain in ignored `labs/lab10/work/`; the credentials file is mode 0600. Public aggregates are in [`lab10-metrics.json`](lab10-metrics.json).

## Task 1

### Stand up, authenticate and import

```bash
git clone --branch 2.58.3 --depth 1 \
  https://github.com/DefectDojo/django-DefectDojo.git labs/lab10/work/dd
cd labs/lab10/work/dd
./docker/setEnv.sh release
DJANGO_VERSION=2.58.3 NGINX_VERSION=2.58.3 docker compose -p lab10 pull
# .env pins both images and supplies random Django/AES secrets.
# Local override restricts nginx's ports to 127.0.0.1:8080 and :8443.
docker compose -p lab10 up -d --no-build
```

The initializer completed successfully. Its admin password was read into a protected local file without printing it, and `POST /api/v2/api-token-auth/` returned a token. Product type **1: Research and Development** matches the importer. I created product **1: OWASP Juice Shop** and engagement **1: Course Semester Run**, type CI/CD, dates **2026-09-01–2026-12-15**, status In Progress.

```bash
# DD_URL and DD_TOKEN are loaded from local credentials, without echoing them.
export DD_URL=http://127.0.0.1:8080
bash labs/lab10/imports/run-imports.sh
```

The first run exited **1**, correctly identifying the ZAP format failure; a zero-finding Kubernetes import also exposed a schema mismatch. DefectDojo 2.58.3's `ZAP Scan` parser requires **XML**, while the original report is JSON. `Trivy Operator Scan` requires Operator CRD reports, while the saved `trivy-k8s.json` is **Trivy CLI** output with `ClusterName` and `Findings`. The regular `Trivy Scan` parser handles the resource structure under `Resources` in this version.

I added [`prepare-report.py`](../labs/lab10/imports/prepare-report.py): it converts the saved ZAP alerts/instances to XML and renames Trivy's `Findings` to `Resources`, retaining every resource's identity, metadata and results. The importer now prepares these inputs automatically and selects `Trivy Scan` for the CLI Kubernetes report. Verification confirmed **all 22 ZAP alerts and their instance counts/required fields**, and exact equality of the complete Trivy resource evidence. Both repaired imports exited **0**, with no missing-report skips:

```bash
DD_IMPORT_ONLY=auth-report.json bash labs/lab10/imports/run-imports.sh
DD_IMPORT_ONLY=trivy-k8s.json bash labs/lab10/imports/run-imports.sh
```

### Import inventory

Counts are imported finding **records**, not unique vulnerabilities or raw scanner totals. The last column is the final active count after reconciliation.

| Source report | Actual parser | Test | Imported records | Final active |
|---|---|---:|---:|---:|
| Lab 4 `grype-from-sbom.json` | Anchore Grype | 1 | 183 | 183 |
| Lab 4 `trivy.json` | Trivy Scan | 2 | 177 | 177 |
| Lab 5 `semgrep.json` | Semgrep JSON Report | 3 | 27 | 27 |
| Lab 5 `auth-report.json` → XML | ZAP Scan | 10 | 22 | 22 |
| Lab 6 `checkov-terraform/results_json.json` | Checkov Scan | 5 | 80 | 80 |
| Lab 6 `kics-ansible/results.json` | KICS Scan | 6 | 10 | 10 |
| Lab 6 `kics-pulumi/results.json` | KICS Scan | 7 | 6 | 6 |
| Lab 7 `trivy-image.json` | Trivy Scan | 8 | 87 | 13 |
| Lab 7 `trivy-k8s.json` → Resources schema | Trivy Scan | 11 | 174 | 0 |
| **Total** | | | **766** | **518** |

The initially failed ZAP test 4 and empty Operator test 9 are retained with zero findings for auditability and contribute nothing to these totals. Trivy imports secrets as well as vulnerabilities: the Lab 7 image report's 85 vulnerability records become 87 imported findings. The cluster report contains repeated results for application/init-container image content, explaining 174 records; zero **final active** means those issues are represented by canonical records, not that the deployment is vulnerability-free.

### Deduplication and severity

The stock instance had `enable_deduplication=false`. I changed it to true through `PATCH /api/v2/system_settings/1/`, then ran:

```bash
docker exec lab10-uwsgi-1 python manage.py dedupe --dedupe_only --dedupe_sync
```

Built-in deduplication marked **162** duplicates, reducing active findings from **766 to 604**. I reviewed the remaining image/cluster matches on the same Juice Shop artifact; [`reconcile-trivy.py`](../labs/lab10/imports/reconcile-trivy.py) matched advisory, component, version, normalized path and severity, with canonical records chosen by oldest date. Its read-only plan identified **86** matches; applying them through DefectDojo's `set_duplicate` helper left **248 duplicate records and 518 active canonical records**. Duplicate evidence remains linked to the canonical findings. This script requires prior confirmation that the supplied tests scan the same artifact; it must not be used to collapse unrelated deployments.

```bash
docker exec -i -e DD_PRODUCT_ID=1 \
  -e 'DD_CANONICAL_TESTS=[2,8]' -e 'DD_DUPLICATE_TESTS=[11]' \
  lab10-uwsgi-1 python manage.py shell < labs/lab10/imports/reconcile-trivy.py
# After inspecting the plan, repeat with -e DD_APPLY=true.
```

| Severity | Active findings |
|---|---:|
| Critical | 25 |
| High | 189 |
| Medium | 241 |
| Low | 51 |
| Info | 12 |
| **Total** | **518** |

These remain **canonical scanner records**, not a proved count of distinct exploitable risks. Cross-tool Grype/Trivy advisory aliases and reachability need review; the old Grype report lacks a verifiable immutable image identity, so I did not automatically merge it with Trivy. Checkov findings with no vendor severity receive the parser's default Medium severity, which must not substitute for exposure/IAM-impact triage. Built-in Trivy grouping can combine different installed paths of the same vulnerable package/version; remediation must inventory all affected paths even where the dashboard has one record.

### Two repeated titles, different decisions

- **`NSWG-ECO-428 Base64url 0.0.6`**: IDs **236** (Lab 4 Trivy), **488** (Lab 7 image), **597/684** (Lab 7 cluster) share the advisory, package/version and `juice-shop/node_modules/base64url/package.json` location. The cluster/image describe the same pinned Juice Shop content, and this is repeated evidence of one package issue, not four independently remediable defects. The later records are linked to the canonical earlier finding.
- **`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`**: IDs **379** and **382** identify `routes/login.ts` and `routes/search.ts`, respectively. They are two code locations with separate routes and fixes, not one issue repeated because the rule title matches. Other matches with this title are in challenge/code-fix examples and need a different scope decision; I retained their locations instead of merging by title.

This week I would act on Lab 5's runtime SQL injection/reflected XSS evidence and corresponding application routes, Lab 6's unrestricted IAM/public-exposure/secrets findings, and the fixable critical/high dependencies from Labs 4 and 7. Labs 1–3 contribute scope, threat priorities and Git/secret controls rather than importable vulnerability counts; Labs 8–9 contribute integrity and detection evidence. Noise includes Semgrep matches in teaching/code-fix examples, ZAP informational detections, repeated dependency sightings and IaC sample issues that were never deployed. They require scope/reachability decisions or root-cause grouping, rather than deleting all inconvenient findings or treating every scanner record as an independent emergency.

## Task 2

### Applied SLA policy

I created **SLA configuration 3: Course Risk SLA** through `POST /api/v2/sla_configurations/` and assigned it to product 1 with `PATCH /api/v2/products/1/`. Enforcement is enabled for all four severities; `restart_sla_on_reactivation=false`. The stock Default configuration is retained unchanged, so unrelated future products keep their existing policy.

| Severity | Default days | Applied days | Rationale |
|---|---:|---:|---|
| Critical | 7 | 3 | Contain immediately and prioritize an emergency fix/rebuild for confirmed reachable critical impact; three days is the remediation target, not permission to leave exposure untouched. |
| High | 30 | 14 | Two weeks provides a normal engineering cycle while prioritizing validated injection, privilege reach and exposed secrets. |
| Medium | 90 | 45 | Resolve within the next few planned cycles; elevate default-rated IaC findings if actual privilege or exposure warrants it. |
| Low | 120 | 90 | Quarterly maintenance fits low-impact changes, with exceptions reviewed before they expire. |

Information findings have no enforced deadline in this configuration. These are proposed operating targets applied to the teaching product, not a claim that all critical scanner records are reachable or that a production team has agreed to this capacity.

### Active findings by tool

| Source parser | Active canonical records |
|---|---:|
| Anchore Grype | 183 |
| Trivy Scan | 190 |
| Semgrep JSON Report | 27 |
| Checkov Scan | 80 |
| KICS Scan | 16 |
| ZAP Scan | 22 |
| **Total** | **518** |

The severity table above and this source table use exactly the same active population. Source attribution uses the canonical finding's test parser; merged cluster evidence is retained even though its own final active contribution is zero.

### Age and SLA calculations

Importing old reports initially dated findings **2026-10-11**, which would have reset their apparent ages. I restored the evidenced scan dates using [`restore-scan-dates.py`](../labs/lab10/imports/restore-scan-dates.py): **2026-09-21** for Lab 4 (Trivy `CreatedAt` and Grype descriptor timestamp), **2026-09-27** for Labs 5–6 (retained run reports), and **2026-10-04** for Lab 7 (retained run report/scan). Both `date` and `sla_start_date` use that original date, and expiry dates were recomputed against the assigned product SLA. This restoration modified all **766** records; it does not assert that these vulnerabilities were first introduced on those scan dates.

```bash
docker exec -i -e DD_PRODUCT_ID=1 \
  -e 'DD_TEST_DATES={"1":"2026-09-21","2":"2026-09-21","3":"2026-09-27","5":"2026-09-27","6":"2026-09-27","7":"2026-09-27","8":"2026-10-04","10":"2026-09-27","11":"2026-10-04"}' \
  lab10-uwsgi-1 python manage.py shell < labs/lab10/imports/restore-scan-dates.py
DD_PRODUCT_ID=1 DD_AS_OF=2026-10-11 \
  python3 labs/lab10/imports/collect-metrics.py submissions/lab10-metrics.json
```

[`collect-metrics.py`](../labs/lab10/imports/collect-metrics.py) reads every page of `/api/v2/findings/?test__engagement__product=1&limit=1000` and joins tests to source tools. The active population requires `active=true`, `duplicate=false`, `false_p=false`, `out_of_scope=false` and `is_mitigated=false`; all 518 active records satisfy that filter.

| Metric as of 2026-10-11 | Value | Calculation |
|---|---:|---|
| Median age | **20 days** | Median of `2026-10-11 - finding.date` across 518 active records. |
| Oldest age | **20 days** | Maximum of the same date differences; oldest retained scan is 2026-09-21. |
| Inside enforced SLA | **65.22%** | `330 / 506 × 100`, where expiry date is on or after 2026-10-11. |

There are **176 overdue findings: 25 Critical and 151 High**. A finding due today is inside SLA until that day ends. The **12 Info findings have no enforced SLA** and are excluded from the 506-record denominator; for the literal share of *all* active findings that have a deadline and are inside it, the result is **330/518 = 63.71%**. Reporting 100% based on today's import date would have obscured the old backlog.

Labs 8 and 9 produced signature/attestation verification and runtime/policy alerts that these vulnerability metrics do not include; retain them as linked control evidence keyed by image digest, and create a Generic Findings Import or incident ticket for actionable verification failures/runtime detections rather than silently treating them as zero findings.

### Expiring risk acceptance

I would accept **finding 588, “Timestamp Disclosure - Unix” (Low, ZAP)** for the confined teaching environment until **2026-11-10**, owned by the lab maintainer. The compensating control is local-only access/authorized port-forwarding, no real user data or credentials, and stopping the vulnerable target outside exercises; require confirmation of that isolation before applying the exception to a running deployment. It does not apply to SQL injection, XSS, or any public deployment. Reassess on 2026-11-10 or immediately if exposure changes; remove the unnecessary timestamp or renew only with recorded justification. This is a documented proposed exception, **not** an API-applied risk acceptance or a claim that severity alone proves harmlessness.

### Executive summary

The project has **518 active canonical scanner findings**, including **25 Critical**, and only **65.22%** of findings with enforced deadlines remain inside SLA after preserving their original scan dates. The biggest validated application risk is the Lab 5 SQL injection evidence, which should drive route-level validation and remediation ahead of cosmetic alert suppression. To close it, assign an application owner and engineering time for parameterized queries plus regression/DAST verification, while keeping Juice Shop isolated and triaging the overdue critical/high dependency and infrastructure backlog.

## Bonus

The interview script is [`lab10-walkthrough.md`](lab10-walkthrough.md), approximately 700 words for five minutes at a measured pace. The hardest part to explain concisely was the difference between raw scanner records, deduplicated findings and independently remediable risks. It is tempting to call a reduction in dashboard totals a security fix, even though most of this reduction came from grouping repeated evidence. Next time I would record each finding's artifact, scope, original detection date, remediation owner and verification evidence as the work happens, rather than reconstructing that history at the capstone.

## Reproducibility and cleanup

All helpers use the retained reports or actual local Dojo state; no fabricated alerts or metric fixtures were imported. Syntax checks passed for the importer and Python helpers; converter checks preserved evidence; the final metric export checks product scope, pagination and actual expiry dates. The initial failed imports and repair logs are retained locally, making the recovery reviewable. DefectDojo was stopped with `docker compose -p lab10 down` after capture, retaining its volumes so the imported product can be reopened with `docker compose -p lab10 up -d --no-build` in `labs/lab10/work/dd`.

DefectDojo's [deduplication documentation](https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/) explains why parser-specific identity matters; the pinned source parsers were inspected to resolve the format mismatches rather than assuming a successful HTTP response proved coverage.
