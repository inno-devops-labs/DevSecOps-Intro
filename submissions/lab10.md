# Lab 10 — DefectDojo Capstone and Governance

## Task 1

I used DefectDojo **2.58.3**

| Source file | Parser used | Test ID | Active findings |
|---|---|---:|---:|
| `labs/lab4/grype-from-sbom.json` | Anchore Grype | 1 | 183 |
| `labs/lab4/trivy.json` | Trivy Scan | 2 | 177 |
| `labs/lab5/results/semgrep.json` | Semgrep JSON Report | 3 | 27 |
| `labs/lab5/results/auth-report.json`, converted to XML | ZAP Scan | 10 | 13 |
| `labs/lab6/results/checkov-terraform/results_json.json` | Checkov Scan | 5 | 80 |
| `labs/lab6/results/kics-ansible/results.json` | KICS Scan | 6 | 10 |
| `labs/lab6/results/kics-pulumi/results.json` | KICS Scan | 7 | 6 |
| `labs/lab7/results/trivy-image.json` | Trivy Scan | 8 | 89 |
| `labs/lab7/results/trivy-k8s.json` | Trivy Scan | 11 | 178 |

The batch importer initially returned exit code 1 because ZAP Scan rejected JSON with `Wrong file format, please use xml`. I converted the existing JSON alerts and instances to the XML structure expected by the parser, without rescanning or changing their evidence; the retry returned HTTP 201 and imported all 13 alerts. Trivy Operator Scan initially accepted the Kubernetes file but produced zero findings because it expects Operator report objects, while this file contains `ClusterName` and `Resources`. Importing the unchanged file with Trivy Scan returned HTTP 201 and 178 findings; the empty test 9 is excluded from the table and contributes nothing to the totals.

### Active findings

The API returned 763 records for engagement 1; all were active and none had the duplicate flag set.

| Severity | Active findings |
|---|---:|
| Critical | 60 |
| High | 408 |
| Medium | 235 |
| Low | 47 |
| Info | 13 |
| **Total** | **763** |

Query: `GET /api/v2/findings/?test__engagement=1&limit=100`, following every `next` link. Counts use `active == true` and `duplicate == false`. A zero duplicate flag count does not establish that the records represent distinct remediation tasks.

### Two repeated titles

1. **`CVE-2026-93748 HTTP-Cache-Semantics 4.2.0`** appears six times: IDs 509, 510, 611, 612, 700 and 701. The package and version match, but there are two installed paths: under `make-fetch-happen/node_modules` and under `sqlite3/node_modules`. Each path appears in the standalone image scan and twice in the Kubernetes scan, where the application and init container use the same image. I would group these under one dependency remediation with both installed paths and deployment occurrences retained, rather than count six independent vulnerabilities; upgrading only one nested copy would not close both paths.
2. **`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`** appears six times: IDs 371–374, 379 and 382. These are separate code locations, not one record imported twice: four are under `data/static/codefixes/`, while two are in `routes/login.ts:34` and `routes/search.ts:23`. I would review the runtime routes first and classify the static challenge snippets separately after checking whether they execute. Matching the rule title alone is insufficient to deduplicate different source locations.

### What I would act on this week

Lab 5 contributes the most direct application investigation: ZAP reported SQL Injection, and Semgrep identified potentially unsafe database operations in the login and search routes, so I would validate reachability and replace unsafe query construction where confirmed. Labs 4 and 7 contribute vulnerable dependencies and container findings that I would group by component, version and deployed image before prioritizing reachable Critical/High issues with available fixes. Lab 6 contributes exposed infrastructure and credential patterns that deserve resource-level review, whereas static challenge snippets, repeated app/init-container image records and low-value disclosure alerts inflate the queue without representing equally urgent independent fixes. Labs 1–3 supplied deployment, threat-model and repository controls, while Labs 8–9 supplied integrity, policy and runtime evidence; their absence from these imported scan totals does not make them irrelevant.

## Task 2

### SLA decisions

Configuration 1 was updated through `PATCH /api/v2/sla_configurations/1/` and explicitly assigned through `PATCH /api/v2/products/1/` with `{"sla_configuration":1}`.

| Severity | Default days | Selected days | Reason |
|---|---:|---:|---|
| Critical | 7 | 7 | Retain the urgent one-week deadline; validate exposure immediately and apply containment while preparing the fix. |
| High | 30 | 14 | Shorten to a two-week remediation cycle because reachable application and dependency issues should not wait a month. |
| Medium | 90 | 30 | Shorten to one month so confirmed issues receive attention within the remaining course period. |
| Low | 120 | 90 | Shorten the review horizon while preserving capacity for higher-impact work; any exception needs a named reason and expiry. |

All four enforcement flags remain true. These are remediation targets for confirmed findings, not a claim that all 763 records are independent or equally exploitable.

### Active findings by source tool

| Tool | Active findings |
|---|---:|
| Grype | 183 |
| Trivy | 444 |
| Semgrep | 27 |
| Checkov | 80 |
| KICS | 16 |
| ZAP | 13 |
| **Total** | **763** |

Trivy combines tests 2, 8 and 11; KICS combines tests 6 and 7. The severity breakdown is shown in Task 1.

### Age and compliance

| Metric | Result | Method |
|---|---:|---|
| Median active age | 0 days | `statistics.median(f["age"] for f in active)` |
| Oldest active age | 0 days | `max(f["age"] for f in active)` |
| Within configured SLA | 100% (750/750) | Count applicable active findings where `age <= selected_sla[severity]`, then divide by all applicable active findings. |

The source was the paginated engagement findings query above. Info has no configured deadline, so its 13 records are reported separately and excluded from the SLA denominator. Every finding has `date=2026-10-12`; the zero age reflects today's import date, not when the underlying weakness first existed, and 100% compliance does not demonstrate remediation performance.

### Evidence gap

These totals omit Lab 8 signature/attestation verification and tamper tests, plus Lab 9 Falco runtime alerts and Conftest policy results; I would link that evidence to the relevant image digest or deployment and track failed controls separately from package and application findings.

### Proposed risk acceptance

I would temporarily accept **finding #579, Private IP Disclosure (Low), from ZAP test 10**, to verifying that the training target is accessible only from the local machine and isolated from production networks. Local-only access and the absence of production credentials/data would be the compensating controls; acceptance is conditional on checking those controls, not a claim that they have already been verified for every current container. I would own the review on that date, remove the disclosed address or renew the exception with fresh justification, and revoke the exception earlier if the target became externally accessible.

### Executive summary

The project has 763 active imported findings, including 60 Critical and 408 High, with several repeated component and deployment observations still requiring triage. The biggest immediate risk to investigate is the potentially exploitable SQL injection in the authentication/search paths, supported by both dynamic and source-level evidence. I need an application owner to validate those paths and implement parameterized queries, plus time to group dependency occurrences and schedule confirmed fixes against the deadlines.

## Bonus

The hardest part to explain concisely was why image hardening, image signing and vulnerability remediation answer different questions even when they concern the same artifact. The read-only filesystem removed a configuration weakness but did not remove vulnerable packages, and a valid signature established integrity rather than safety. In the next project I would record each decision beside its exact artifact, validation command and remaining limitation. I would also retain scan dates and component occurrences so the final dashboard distinguishes remediation work from repeated observations.
