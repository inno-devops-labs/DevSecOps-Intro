# Lab 10 — Vulnerability Management: The Capstone

## Task 1

DefectDojo was run at version `2.58.3`. The product type used for the product was `Research and Development`, and the product/engagement created for the lab was `OWASP Juice Shop` / `Course Semester Run`.

| Source file | Parser | Active findings |
|---|---|---:|
| `labs/lab4/grype-from-sbom.json` | Anchore Grype | 189 |
| `labs/lab4/trivy.json` | Trivy Scan | 204 |
| `labs/lab5/results/semgrep.json` | Semgrep JSON Report | 27 |
| `labs/lab5/results/auth-report.json` converted to `labs/lab10/work/evidence/auth-report.xml` | ZAP Scan | 13 |
| `labs/lab6/results/checkov-terraform/results_json.json` | Checkov Scan | 80 |
| `labs/lab6/results/kics-ansible/results.json` | KICS Scan | 10 |
| `labs/lab6/results/kics-pulumi/results.json` | KICS Scan | 6 |
| `labs/lab7/results/trivy-image.json` | Trivy Scan | 87 |
| `labs/lab7/results/trivy-k8s.json` | Trivy Operator Scan | 0 |

The batch import command was:

```bash
bash labs/lab10/imports/run-imports.sh
```

Relevant output from the batch import run:

```text
Importing Anchore Grype from labs/lab4/grype-from-sbom.json
  ok: test 9, 189 active findings
Importing Trivy Scan from labs/lab4/trivy.json
  ok: test 11, 204 active findings
Importing Semgrep JSON Report from labs/lab5/results/semgrep.json
  ok: test 12, 27 active findings
Importing ZAP Scan from labs/lab5/results/auth-report.json
Importing Checkov Scan from labs/lab6/results/checkov-terraform/results_json.json
  ok: test 14, 80 active findings
Importing KICS Scan from labs/lab6/results/kics-ansible/results.json
  ok: test 15, 10 active findings
Importing KICS Scan from labs/lab6/results/kics-pulumi/results.json
  ok: test 16, 6 active findings
Importing Trivy Scan from labs/lab7/results/trivy-image.json
  ok: test 17, 87 active findings
Importing Trivy Operator Scan from labs/lab7/results/trivy-k8s.json
  ok: test 18, 0 active findings
```

The final parser/count summary below is the evidence for the report counts, including the ZAP XML import result.

The imported parser/count summary was checked with:

```bash
awk -F '\t' '{print $2, $5}' labs/lab10/work/evidence/import-summary.tsv
```

```text
parser active_findings
Anchore Grype 189
Trivy Scan 204
Semgrep JSON Report 27
ZAP Scan 13
Checkov Scan 80
KICS Scan 10
KICS Scan 6
Trivy Scan 87
Trivy Operator Scan 0
```

Active findings from the DefectDojo API totaled **616**.

| Severity | Active findings |
|---|---:|
| Critical | 37 |
| High | 258 |
| Medium | 248 |
| Low | 60 |
| Info | 13 |

The active total and severity counts were checked with:

```bash
jq -r '.active_total' labs/lab10/work/evidence/metrics-summary.json
jq -r '.[] | "\(.severity) \(.count)"' labs/lab10/work/evidence/active-severity.json
```

```text
616
Critical 37
High 258
Info 13
Low 60
Medium 248
```

The repeated titles were listed with:

```bash
jq -r '.[] | "\(.n)  \(.title)"' labs/lab10/work/evidence/duplicate-titles.json | head -6
```

```text
7  Secret Management: Passwords and Secrets - Generic Password
6  javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
5  yaml.github-actions.security.run-shell-injection.run-shell-injection
4  yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag
4  javascript.express.security.audit.express-res-sendfile.express-res-sendfile
4  javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing
```

Two repeated titles stood out. `Secret Management: Passwords and Secrets - Generic Password` appeared 7 times, but these should be treated as separate findings because DefectDojo showed different IaC files and lines, including Ansible inventory/playbook locations and one Pulumi YAML location. `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` appeared 6 times; these are also separate source locations under the same Semgrep rule, with the most important ones being `routes/login.ts:34` and `routes/search.ts:23`.

Labs 1–3 did not contribute scanner reports to this DefectDojo import flow, so they are not represented in the finding counts above. Labs 4 and 7 produced the dependency and image findings that should be triaged first, especially Critical and High issues with available fixes. Lab 5 produced the clearest application risk because Semgrep and ZAP both pointed to SQL-injection-related weaknesses, while Lab 6 produced actionable IaC findings but also noise from repeated rule titles and intentionally vulnerable teaching examples. Labs 8 and 9 produced signing, attestation, runtime detection, and policy-as-code evidence, but those controls were not included in DefectDojo scanner counts because this lab did not provide parsers for them.

## Task 2

The stock DefectDojo `Default` SLA was changed from `critical=7 high=30 medium=90 low=120` days to `critical=1 high=7 medium=30 low=90` days.

| Severity | Default SLA | Configured SLA | Reason |
|---|---:|---:|---|
| Critical | 7 days | 1 day | Critical findings need a next-day response because they represent the highest immediate risk. |
| High | 30 days | 7 days | High findings should enter the weekly remediation cycle instead of waiting a full month. |
| Medium | 90 days | 30 days | Medium findings still matter, but one month gives time for normal planning. |
| Low | 120 days | 90 days | Low findings can be handled later, but they should not stay open indefinitely. |

The before/after `Default` SLA values were checked with:

```bash
jq -r '.results[] | select(.name=="Default") | "critical=\(.critical) high=\(.high) medium=\(.medium) low=\(.low)"' labs/lab10/work/evidence/sla-before.json
jq -r '.results[] | select(.name=="Default") | "critical=\(.critical) high=\(.high) medium=\(.medium) low=\(.low)"' labs/lab10/work/evidence/sla-after.json
```

```text
critical=7 high=30 medium=90 low=120
critical=1 high=7 medium=30 low=90
```

Active findings by severity:

| Severity | Active findings |
|---|---:|
| Critical | 37 |
| High | 258 |
| Medium | 248 |
| Low | 60 |
| Info | 13 |

Active findings by source tool:

| Source tool | Active findings |
|---|---:|
| Trivy Scan | 291 |
| Anchore Grype | 189 |
| Checkov Scan | 80 |
| Semgrep JSON Report | 27 |
| KICS Scan | 16 |
| ZAP Scan | 13 |
| Trivy Operator Scan | 0 |

The calculation used the saved DefectDojo API response in `labs/lab10/work/evidence/active-findings.json`, collected from `/api/v2/findings/?active=true&limit=2000`. Age and SLA status were calculated from the returned `date` and `sla_expiration_date` fields:

```python
import json
import statistics
from datetime import date

with open("labs/lab10/work/evidence/active-findings.json", encoding="utf-8") as f:
    response = json.load(f)

active = response["results"]
now = date.today()
ages = [(now - date.fromisoformat(f["date"][:10])).days for f in active]
median_age_days = statistics.median(ages)
oldest_age_days = max(ages)
with_sla = [f for f in active if f.get("sla_expiration_date")]
inside_sla = [f for f in with_sla if date.fromisoformat(f["sla_expiration_date"][:10]) >= now]
sla_compliance = len(inside_sla) / len(with_sla) * 100
all_active_with_valid_sla_share = len(inside_sla) / len(active) * 100
```

The same result was checked from the saved summary file:

```bash
cat labs/lab10/work/evidence/metrics-summary.json
```

```json
{
  "active_total": 616,
  "active_by_severity": {
    "High": 258,
    "Critical": 37,
    "Medium": 248,
    "Info": 13,
    "Low": 60
  },
  "active_by_tool": {
    "Anchore Grype": 189,
    "Checkov Scan": 80,
    "KICS Scan": 16,
    "Semgrep JSON Report": 27,
    "Trivy Scan": 291,
    "ZAP Scan": 13
  },
  "calculation_date": "2026-10-09",
  "median_age_days": 1.0,
  "oldest_age_days": 1,
  "inside_sla_count": 603,
  "with_sla_count": 603,
  "sla_compliance_percent": 100.0,
  "inside_sla_percent": 97.89,
  "info_without_sla": 13
}
```

The median active finding age was **1 day**, and the oldest active finding age was also **1 day**, because the findings were imported into this DefectDojo instance during the lab run and recalculated on 2026-10-09. SLA-governed findings totaled **603**, and **603 of 603** were inside SLA, so SLA compliance for governed findings was **100%**. Across all active findings, **603 of 616** had an SLA date and were inside SLA, which is **97.89%**; the remaining **13 Info findings** had no `sla_expiration_date`, so they are treated as N/A rather than out of SLA.

Labs 8 and 9 produced supply-chain signing, attestation, runtime detection, and policy-as-code evidence that is not represented in these scanner numbers, so they should be tracked as manual control evidence linked to the same product and reviewed during release readiness.

The recommended risk acceptance is `GHSA-p6mc-m468-83gw in lodash.set:4.3.2` until **2026-12-15**. DefectDojo reported this High finding with `fix_available=false`, so the short-term decision is to keep the application limited to the lab environment, monitor the dependency in the weekly SCA review, and revisit the acceptance if upstream publishes a fix or if this component becomes reachable in production-like use.

Executive summary: The project currently has 616 active findings in DefectDojo, including 37 Critical and 258 High findings, so the backlog needs prioritization rather than a simple count target. The biggest risk is SQL injection because both static and dynamic testing identified SQL-injection-related weaknesses. Closing the risk requires ownership for the vulnerable routes and dependencies, a weekly remediation queue, and explicit tracking for Labs 8 and 9 controls that do not enter DefectDojo automatically.

## Bonus

The hardest part to explain concisely was the difference between scanner volume and management priority. The project has many findings, but the important message is not just the number 616; it is which findings are reachable, repeated, fixable, or tied to a confirmed runtime behavior. For the next project, documenting the evidence flow earlier would help: scanner source, parser, deduplication rule, owner, SLA, and decision status. That would make the final vulnerability-management story easier to explain without turning it into a tool list.
