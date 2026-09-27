# Lab 6 — Infrastructure as Code Security

Run date: 2026-09-27. Checkov **3.3.19**, Python **3.12.14**.
The original vulnerable infrastructure files were not changed or deployed.
JSON reports and corrected test copies remain in gitignored `labs/lab6/results/`.

All tasks and the custom-policy bonus were executed. KICS reports version **v2.1.20**
from image digest `sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602`.

## Task 1

### Command and framework results

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

| Framework | Passed | Failed | Skipped | Parsing errors |
|---|---:|---:|---:|---:|
| terraform | 49 | 78 | 0 | 0 |
| secrets | 0 | 2 | 0 | 0 |
| Total | 49 | 80 | 0 | 0 |

The output is an array of framework objects. Counts come from each object's
`summary`; findings are collected from `.[].results.failed_checks[]`.

### Five most frequent rules

Ties are ordered by check ID. Descriptions below are taken from the installed
scanner's actual `check_name` fields, rather than inferred from the IDs.

| Rule | Failures | Check description |
|---|---:|---|
| `CKV_AWS_289` | 4 | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| `CKV_AWS_355` | 4 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |
| `CKV_AWS_23` | 3 | Ensure every security group and rule has a description |
| `CKV_AWS_288` | 3 | Ensure IAM policies does not allow data exfiltration |
| `CKV_AWS_290` | 3 | Ensure IAM policies does not allow write access without constraints |

### One change with high leverage

Replace the wildcard statement in `terraform/iam.tf`, resource
`aws_iam_policy.admin_policy`, with an application-specific allowlist. For a
hypothetical read-only workload, the tested replacement is:

```hcl
Effect   = "Allow"
Action   = "s3:GetObject"
Resource = "arn:aws:s3:::my-public-bucket-lab6/app/*"
```

This is a demonstrable least-privilege example; the actual application requirements
would determine the final bucket and prefix. A scan of a temporary copy confirms
that this one policy-statement change clears **nine failures**:
`CKV_AWS_62`, `CKV_AWS_63`, `CKV_AWS_286`, `CKV_AWS_287`, `CKV_AWS_288`,
`CKV_AWS_289`, `CKV_AWS_290`, `CKV_AWS_355`, and `CKV2_AWS_40`.
Terraform changes from **49 passed / 78 failed** to **58 passed / 69 failed**;
the two secrets findings are unchanged. Reports are retained under
`results/checkov-iam-fix/`.

The database resource has more findings in total (12), but they require several
independent settings; that is different from nine checks reacting to one broad IAM
statement. The nine alerts are overlapping consequences of one permission design,
so fixing that statement once is not nine separate remediation tasks. Across real
module instances, fixing a shared policy generator would prevent the same defect
recurring, but this sample contains separate resources, not a shared module.

### Prioritising without vendor severity

All 80 failed findings have null severity. In a real backlog I would rank confirmed
internet exposure, privilege reach, sensitive data and exploitability first, then
use shared root cause and remediation effort to find changes with broad benefit.
Purchased severity can enrich that process, but it cannot establish the deployment
context or turn correlated rule matches into independent risks.

## Task 2

### Commands

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/labs/lab6:/path" \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/ansible/ \
  -o /path/results/kics-ansible/ --report-formats json,sarif

docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/labs/lab6:/path" \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/pulumi/ \
  -o /path/results/kics-pulumi/ --report-formats json,sarif
```

Both scans completed and produced JSON and SARIF. Exit status 60 indicates findings.
Ansible parsed 3 files; Pulumi parsed 1. Neither reported file-scan or query-execution
failures. The Pulumi infrastructure findings name `Pulumi-vulnerable.yaml`; these
results do not demonstrate analysis of the Python `__main__.py` program.

### Severity breakdown: queries versus individual findings

| Severity | Ansible queries | Ansible findings | Pulumi queries | Pulumi findings |
|---|---:|---:|---:|---:|
| Critical | 0 | 0 | 1 | 1 |
| High | 3 | 9 | 2 | 2 |
| Medium | 0 | 0 | 1 | 1 |
| Low | 1 | 1 | 0 | 0 |
| Info | 0 | 0 | 2 | 2 |
| Total | 4 | 10 | 6 | 6 |

Queries count `.queries[]`; findings use `.severity_counters` and match the sum of
`.queries[].files | length`. Despite the field name, `files` contains finding
locations and can repeat the same filename.

### Top Ansible queries

Only four queries fired, so there is no fifth query to list. The table is sorted
by the assignment's `.files | length` metric and also gives distinct file counts.

| Query | Severity | Finding locations | Distinct files |
|---|---|---:|---:|
| Passwords And Secrets - Generic Password | High | 6 | 3 |
| Passwords And Secrets - Password in URL | High | 2 | 1 |
| Passwords And Secrets - Generic Secret | High | 1 | 1 |
| Unpinned Package Version | Low | 1 | 1 |

For example, the password query finds four locations in `inventory.ini`, one in
`configure.yml`, and one in `deploy.yml`. Password-in-URL findings are at
`deploy.yml:16` and `deploy.yml:72`; the unpinned package is at `deploy.yml:99`.

### Coverage differences

**KICS finding absent from the Checkov run:** `RDS DB Instance Publicly Accessible`
at `pulumi/Pulumi-vulnerable.yaml:104` (Critical). KICS recognises the Pulumi YAML
resource and its `publiclyAccessible: true` property. The Checkov Terraform scan
cannot interpret that Pulumi manifest as Terraform; it does catch the corresponding
public-RDS defect in the separate HCL sample. The distinction is input coverage,
not proof that Checkov lacks a public-database rule. KICS's Ansible
`Unpinned Package Version` finding is likewise outside the inputs of Task 1.

**Checkov class absent from the KICS results:** S3 lifecycle configuration and
cross-region replication, `CKV2_AWS_61` and `CKV_AWS_144`, each fail on both HCL
buckets. To avoid attributing this merely to different inputs, I also ran KICS on
`vulnerable-iac/terraform/`, retaining `results/kics-terraform-control/results.json`.
That control parses the same HCL and reports bucket ACL, logging and versioning
issues, but no lifecycle or replication query. Checkov's HCL resource/relationship
checks cover these missing configurations in this run; the difference here is
query coverage, not an inability of KICS to parse HCL. Neither result establishes
that every version or rule selection has the same gap.

### Pipeline decision

Run Checkov on Terraform and KICS on the supported Ansible and Pulumi YAML inputs,
with tested image digests and retained JSON/SARIF artifacts. Prioritise confirmed
impact and exposure, deduplicate by resource and root cause, and keep query counts
separate from finding counts. For Pulumi Python, inspect rendered infrastructure
or add Pulumi policy tests and code review because this scan only parsed the YAML
sample. Add regression fixtures for confirmed misses and measure coverage before
adding another scanner or accepting a suppression.

## Bonus

### Custom rule

Policy: [`my-custom-policy.yaml`](../labs/lab6/policies/my-custom-policy.yaml).
Every RDS instance must explicitly retain automated backups for **14–35 days**.
The YAML follows Checkov's [custom policy schema](https://www.checkov.io/3.Custom%20Policies/YAML%20Custom%20Policies.html).

The exercise defines a proposed internal standard **DB-01**: support a two-week
recovery window, with retention bounded at 35 days. This is a lab-defined standard,
not a claim that a real organisation adopted it or experienced an incident.
The 14-day minimum is an organisational recovery requirement, whereas a generic
backup-enabled check should accommodate organisations with other recovery needs.

### Failure evidence

```bash
checkov -d labs/lab6/vulnerable-iac/terraform --framework terraform \
  --external-checks-dir labs/lab6/policies --check CKV_CUSTOM_001 \
  --output json --output-file-path labs/lab6/results/checkov-custom/
```

Filtering the actual JSON for check ID, resource and file gives:

```json
[
  {
    "check_id": "CKV_CUSTOM_001",
    "resource": "aws_db_instance.unencrypted_db",
    "file_path": "/database.tf"
  },
  {
    "check_id": "CKV_CUSTOM_001",
    "resource": "aws_db_instance.weak_db",
    "file_path": "/database.tf"
  }
]
```

Summary: **0 passed, 2 failed, 0 parsing errors**. `unencrypted_db` explicitly
retains zero days; `weak_db` omits the attribute. Both violate DB-01.

### Passing change and verification

In a temporary copy, set the following inside **both** RDS resources:

```hcl
backup_retention_period = 14
```

```bash
checkov -d labs/lab6/results/policy-pass --framework terraform \
  --external-checks-dir labs/lab6/policies --check CKV_CUSTOM_001 \
  --output json --output-file-path labs/lab6/results/checkov-custom-pass/
```

Actual summary: **2 passed, 0 failed, 0 parsing errors**. The pass report contains
both `aws_db_instance.unencrypted_db` and `aws_db_instance.weak_db` under
`passed_checks`. The original deliberately vulnerable samples remain unchanged.
