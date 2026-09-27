# Lab 6 — IaC Security: Checkov, KICS, and a Policy You Write

Samples scanned in place under `labs/lab6/vulnerable-iac/`. Tools: Checkov `3.3.4` (Terraform), KICS `checkmarx/kics:latest` (Ansible + Pulumi). All numbers below come from the JSON reports.

## Task 1

### Passed / failed per framework

Checkov ran `terraform` and `secrets` together, so `results_json.json` is an array with one object per framework (queried with `.[].results.failed_checks[]?`, not `.results.failed_checks[]`).

| Framework | Passed | Failed |
|---|---|---|
| terraform | 49 | 78 |
| secrets | 0 | 2 |
| **Total** | **49** | **80** |

The two `secrets` findings are `CKV_SECRET_2` (AWS Access Key) and `CKV_SECRET_6` (Base64 High Entropy String) — the hardcoded `access_key`/`secret_key` in `main.tf`.

### Top five rules by frequency

| Count | Rule | What it checks |
|---|---|---|
| 4 | `CKV_AWS_289` | IAM policy must not allow permissions-management / resource-exposure actions without a resource constraint (i.e. on `*`). |
| 4 | `CKV_AWS_355` | IAM policy must not use `"*"` as a statement's `Resource` for restrictable actions. |
| 3 | `CKV_AWS_23` | Every security group and every rule must have a `description`. |
| 3 | `CKV_AWS_288` | IAM policy must not allow data-exfiltration actions (e.g. `s3:GetObject`) on unconstrained resources. |
| 3 | `CKV_AWS_290` | IAM policy must not allow write access without a resource constraint. |

(`CKV_AWS_382` — no security-group egress to `0.0.0.0/0` on port `-1` — also fires 3 times, tied for fifth.)

The frequency signal is clear: four of the top five are IAM-policy rules, all firing on the same handful of wildcard policies in `iam.tf`.

### The single highest-leverage change

**File `iam.tf`, resource `aws_iam_policy.admin_policy`** (the `Action = "*"`, `Resource = "*"` statement). That one resource fails **9 distinct checks**: `CKV_AWS_62`, `CKV_AWS_63`, `CKV_AWS_286`, `CKV_AWS_287`, `CKV_AWS_288`, `CKV_AWS_289`, `CKV_AWS_290`, `CKV_AWS_355`, and `CKV2_AWS_40` — all of them symptoms of the same root cause, an unconstrained admin grant. Replacing `Action = "*"` / `Resource = "*"` with a scoped action list and specific resource ARNs clears all nine at once.

But **fixing it once is not the same as fixing it five times.** The identical wildcard pattern is copied into `aws_iam_role_policy.s3_full_access`, `aws_iam_user_policy.service_policy`, and `aws_iam_policy.privilege_escalation`. Checkov scores each *resource* independently, so scoping only `admin_policy` leaves the same class of bug live in three other resources. The durable fix is to stop hand-writing policy JSON per resource and route every grant through one reviewed, least-privilege module (or `aws_iam_policy_document` data sources with explicit resources); then a single change to the shared module fixes every consumer, instead of nine green checks on one resource hiding twenty-plus red ones next door.

### `severity` is null — what would you sort by?

Open-source Checkov leaves `severity` null on every finding (severities are a paid Prisma Cloud feature; no flag turns them on), so I triaged by **frequency** here. In a real backlog I would not sort by raw frequency either — I would sort by **blast radius / exploitability**: is the resource internet-reachable, does it hold data, does it grant privilege escalation. By that measure the hardcoded AWS key (`CKV_SECRET_2`) and the `Action:* Resource:*` policy outrank two dozen "missing description" findings, even though frequency alone would bury them. The lesson about buying severity from a vendor: a vendor severity is a *generic* prior (CVSS-style, context-free), useful for a first cut but not a substitute for knowing which of *your* resources are exposed — so it is worth having as a sort key, but you still have to re-rank by your own environment, which is exactly the judgement the paid column cannot make for you.

## Task 2

### Severity breakdowns (both scans)

KICS assigns severities. Note the arithmetic: the numbers below labelled **findings** come from `severity_counters` (individual results, matching the terminal totals); the **queries** counts come from `.queries | length` (distinct queries). They differ because one query can match several files.

**Ansible** (`vulnerable-iac/ansible/`) — 4 distinct queries, 10 findings:

| Severity | Queries | Findings |
|---|---|---|
| HIGH | 3 | 9 |
| LOW | 1 | 1 |
| **Total** | **4** | **10** |

**Pulumi** (`vulnerable-iac/pulumi/`) — 6 distinct queries, 6 findings (one file each):

| Severity | Queries | Findings |
|---|---|---|
| CRITICAL | 1 | 1 |
| HIGH | 2 | 2 |
| MEDIUM | 1 | 1 |
| INFO | 2 | 2 |
| **Total** | **6** | **6** |

### Top five Ansible queries by files touched

There are only four Ansible queries in total, so all four:

| Files | Severity | Query |
|---|---|---|
| 6 | HIGH | Passwords And Secrets - Generic Password |
| 2 | HIGH | Passwords And Secrets - Password in URL |
| 1 | HIGH | Passwords And Secrets - Generic Secret |
| 1 | LOW | Unpinned Package Version |

Almost everything KICS surfaces in the Ansible sample is a hardcoded secret; the README lists 26 intended issues, but KICS's default query set only reliably matches the secrets and the `state: latest` unpinned package — the SSH/sudo/SELinux misconfigurations are described in free-form task text KICS does not model as policy.

### One finding in each direction, explained by parsing ability

- **KICS reports, Checkov does not:** `RDS DB Instance Publicly Accessible` (CRITICAL) on the Pulumi `unencryptedDb` in `Pulumi-vulnerable.yaml`. Checkov 3.x has **no Pulumi framework** — it expects rendered Terraform state / HCL, not Pulumi's YAML resource model — so it cannot parse this file at all and reports nothing for it. KICS has first-class Pulumi-YAML support, so it walks the resource tree and evaluates `publiclyAccessible: true`.
- **Checkov covers, KICS did not:** deep **IAM policy-document analysis** — data exfiltration / privilege escalation / unconstrained wildcard resource (`CKV_AWS_288/289/290/355`, `CKV2_AWS_40`) on the Terraform `admin_policy`. KICS parsed the *same* wildcard IAM policy in the Pulumi YAML (`adminPolicy`, `Action:*`/`Resource:*`) but shipped no query that flags it, so it stayed silent. Checkov renders the JSON policy document into a graph and reasons about the action/resource pair; that policy-graph capability is what KICS's query set lacked here.

### Pipeline decision and the gap

Two scanners, three formats (Terraform HCL, Pulumi YAML, Ansible YAML), two different verdicts — so the honest answer is **run both, gated by what each parses best**: Checkov on Terraform (its IAM/graph analysis and ~2,500 policies are the strongest there) and KICS on Pulumi and Ansible (the only one of the two that parses them at all). I would fail the pipeline on HIGH/CRITICAL from either and warn on the rest. The gap between them is real and dangerous — each tool is *silent*, not *clean*, on formats or checks it doesn't cover, and a green KICS run on Pulumi does not mean the IAM policy is safe. I would close it by (a) normalising both into SARIF and loading them into one dashboard (Lab 10's DefectDojo) so a missing finding is visible as a coverage gap, not mistaken for a pass, and (b) writing custom policies (below) for the org-specific rules neither ships.

## Bonus

### The policy in one sentence

`labs/lab6/policies/my-custom-policy.yaml` (`CKV_CUSTOM_1`): **every `aws_db_instance` must carry a `CostCenter` tag** so that database spend is attributable to a team for chargeback.

```yaml
metadata:
  id: "CKV_CUSTOM_1"
  name: "Ensure every RDS instance carries a CostCenter tag for chargeback"
  category: "GENERAL_SECURITY"
  severity: "MEDIUM"
definition:
  and:
    - cond_type: "filter"
      attribute: "resource_type"
      operator: "within"
      value:
        - "aws_db_instance"
    - cond_type: "attribute"
      resource_types:
        - "aws_db_instance"
      attribute: "tags.CostCenter"
      operator: "exists"
```

### JSON showing it fire

```json
[
  { "check_id": "CKV_CUSTOM_1", "resource": "aws_db_instance.unencrypted_db", "file_path": "\\database.tf" },
  { "check_id": "CKV_CUSTOM_1", "resource": "aws_db_instance.weak_db",        "file_path": "\\database.tf" }
]
```

Both RDS instances in `database.tf` carry only a `Name` tag, so both fail.

### The change that makes it pass, and confirmation

Add a `CostCenter` tag to each `aws_db_instance` `tags` block, e.g.:

```hcl
  tags = {
    Name       = "Unencrypted Database"
    CostCenter = "CC-1234"
  }
```

Confirmed on a copy of the sample (the sample itself is left broken per the lab): after adding the tag, `checkov --check CKV_CUSTOM_1` reports **`Passed checks: 2, Failed checks: 0`** — `PASSED for resource: aws_db_instance.unencrypted_db` and `PASSED for resource: aws_db_instance.weak_db`.

### Why this rule is mine, not something Checkov should ship

Checkov and KICS ship *security* hygiene — encryption, public access, wildcards — rules that apply to everyone. A mandatory `CostCenter` tag is not a security control; it is our **internal FinOps standard**: after an audit finding that ~30% of RDS spend could not be attributed to a team during last quarter's cost review, Finance mandated that every managed database be taggable to a cost centre before it can be provisioned. That rule is meaningful only inside our chargeback model, so no upstream catalog would (or should) ship it — it has to live as a custom policy in our own pipeline.
