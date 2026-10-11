# Lab 10 — Vulnerability Management: The Capstone

DefectDojo **2.58.3** was run from the pinned `release` Docker Compose stack. Because port `8080` was already used by another local container, I exposed this instance on `http://127.0.0.1:8081`. The product was `OWASP Juice Shop`, product type `Research and Development`, engagement `Course Semester Run`.

## Task 1

### Imported reports

| Lab | File | Parser | Active findings |
|---|---|---|---:|
| 4 | `labs/lab4/grype-from-sbom.json` | Anchore Grype | 182 |
| 4 | `labs/lab4/trivy.json` | Trivy Scan | 176 |
| 5 | `labs/lab5/results/semgrep.json` | Semgrep JSON Report | 27 |
| 5 | `labs/lab5/results/auth-report.json` converted to ZAP XML | ZAP Scan | 13 |
| 6 | `labs/lab6/results/checkov-terraform/results_json.json` | Checkov Scan | 80 |
| 6 | `labs/lab6/results/kics-ansible/results.json` | KICS Scan | 10 |
| 6 | `labs/lab6/results/kics-pulumi/results.json` | KICS Scan | 6 |
| 7 | `labs/lab7/results/trivy-image.json` | Trivy Scan | 87 |
| 7 | `labs/lab7/results/trivy-k8s.json` | Trivy Operator Scan | 0 |

Two parser details mattered. First, DefectDojo 2.58.3 rejected the ZAP JSON report with `Wrong file format, please use xml`, so I converted the same Lab 5 `auth-report.json` into the traditional ZAP XML shape and imported the same 13 alerts. Second, `trivy-k8s.json` imported successfully through `Trivy Operator Scan` but produced 0 findings; I kept that result rather than re-importing it as a different scanner, because the lab asks for the mapped parser and a green import is not the same thing as parsed findings.

### Active findings by severity

| Severity | Count |
|---|---:|
| Critical | 36 |
| High | 253 |
| Medium | 233 |
| Low | 46 |
| Info | 13 |
| **Total active** | **581** |

Query used:

```console
curl -H "Authorization: Token $DD_TOKEN" \
  "$DD_URL/api/v2/findings/?active=true&limit=1000" |
  jq '[.results[].severity] | group_by(.) | map({severity: .[0], count: length})'
```

### Duplicate titles

`Secret Management: Passwords and Secrets - Generic Password` appeared 7 times. I treat these as separate findings, not one duplicate, because the API showed different locations across Ansible and Pulumi files: `inventory.ini` lines 5, 10, 18, 19, `configure.yml:16`, `deploy.yml:12`, and `Pulumi-vulnerable.yaml:16`.

`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` appeared 6 times. These are also separate code findings: two are in real route handlers, `routes/login.ts:34` and `routes/search.ts:23`, while four are in `data/static/codefixes/*.ts` challenge files. Same rule title, different file and line, so this is one weakness class repeated in multiple places rather than a single record counted six times.

### What I would act on this week

The findings I would act on first are from Lab 5 and Labs 4/7. Lab 5 has the strongest evidence because Semgrep points to raw Sequelize sinks and ZAP confirms SQL injection behavior against the running app, especially the product search endpoint. Labs 4 and 7 add fixable Critical/High dependency and image findings such as `crypto-js`, `jsonwebtoken`, `decompress`, and `marsdb`; these affect the shipped artifact and should be triaged with fix availability. Lab 6 is useful but noisier for this week's project risk because the Checkov/KICS findings are mostly in deliberately vulnerable IaC teaching fixtures, and many duplicate rule titles represent multiple sample files rather than production infrastructure.

## Task 2

### SLA numbers

| Severity | Default | Mine | Why |
|---|---:|---:|---|
| Critical | 7 days | **3 days** | Critical findings on an internet-facing app should either be fixed or explicitly contained inside the current week. |
| High | 30 days | **14 days** | Two weeks keeps High findings inside one sprint boundary instead of letting them drift for a month. |
| Medium | 90 days | **45 days** | Medium findings should be planned work, not a quarterly parking lot. |
| Low | 120 days | **90 days** | Low risk can wait, but it should still age out within a quarter. |

Applied through `PATCH /api/v2/sla_configurations/1/`; the API returned `critical=3 high=14 medium=45 low=90`.

### Active findings by severity and source

By severity: Critical 36, High 253, Medium 233, Low 46, Info 13, total 581.

| Source | Active findings |
|---|---:|
| Anchore Grype | 182 |
| Trivy Scan, Lab 4 image/SBOM | 176 |
| Semgrep JSON Report | 27 |
| ZAP Scan | 13 |
| Checkov Scan | 80 |
| KICS Scan, Ansible | 10 |
| KICS Scan, Pulumi | 6 |
| Trivy Scan, Lab 7 image | 87 |
| Trivy Operator Scan | 0 |

### Age and SLA compliance

Method: `GET /api/v2/findings/?active=true&limit=1000`, using DefectDojo's `date` and `sla_days_remaining` fields. The import was performed on **2026-10-11**, and every active finding has `date=2026-10-11`.

| Metric | Value | Calculation |
|---|---:|---|
| Median age of active findings | 0 days | sorted age list midpoint; all active findings were imported today |
| Oldest active finding | 0 days | max age over active findings |
| Inside SLA | 100% of SLA-scoped findings | 568 of 568 findings with `sla_days_remaining` are `>= 0`; 13 Info findings have no SLA clock |

This means the SLA clock is configured, but the compliance number is not yet operationally meaningful because DefectDojo only learned about these findings today. In a real program I would preserve original discovery dates from each scanner import.

### Labs 8 and 9 gap

Lab 8 produced cosign signatures and SBOM attestation evidence; Lab 9 produced Falco runtime alerts and Conftest policy results. None of those appear in the 581 findings because they are control evidence and runtime/policy events, not standard vulnerability scanner records. I would keep cosign verification as a CI release gate and import Falco/Conftest failures as Generic Findings or send them to a SIEM, then create DefectDojo findings only when an event needs owner, severity, and SLA tracking.

### Risk acceptance

I would risk-accept `GHSA-5mrr-rgp6-x4gr in marsdb:0.6.11` until **2026-12-15**, the engagement end date. The reason is that it is a Critical transitive dependency finding in an old Juice Shop dependency tree where a clean upgrade path may be larger than the lab scope. The compensating control is the hardened Lab 7 runtime posture: non-root container, dropped capabilities, read-only root filesystem, and restricted Kubernetes networking from Lab 9, reducing what exploitation can write to or reach. The acceptance must expire on 2026-12-15 and be re-reviewed rather than silently renewed.

### Executive summary

The project now has one DefectDojo view with 581 active findings across SCA, SAST, DAST, IaC, and container-image scanning, but the raw total overstates immediate risk because teaching fixtures and repeated rule titles inflate the backlog. The biggest real risk is SQL injection in the Juice Shop application, because Semgrep identifies the vulnerable source locations and ZAP confirms the behavior against the running service. To close the risk, I need one short development cycle to parameterize the SQL paths, rebuild the image, rerun ZAP/Semgrep/Trivy, and then triage remaining Critical dependency findings under the new 3-day SLA.

## Bonus note

The hardest part to explain concisely was the difference between a raw finding count and a security program. A dashboard can say "581 findings", but it does not automatically tell which are duplicated CVEs, teaching-fixture noise, runtime evidence, or release gates. Next time I would document the decision rule for each control while building it: what it proves, where its evidence lives, whether it creates a DefectDojo finding, and who owns it when it fails.
