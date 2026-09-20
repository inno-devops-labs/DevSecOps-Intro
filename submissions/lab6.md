# Lab 6 - IaC Security

## Environment

Tools used:

- Checkov `3.3.0`
- Docker `28.4.0`
- KICS Docker image `checkmarx/kics:latest`, scanner version `2.1.20`
- `jq 1.7.1`

Checkov was run with:

```bash
checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

## Task 1

### Checkov Results By Framework

The JSON output is an array because Checkov reported both Terraform and secrets findings.

| Framework | Passed | Failed |
| --- | ---: | ---: |
| terraform | 49 | 78 |
| secrets | 0 | 2 |

### Top Five Rules By Frequency

Descriptions are taken from the Checkov rule names/policy index for the IDs in the scan.

| Rule | Count | What it checks |
| --- | ---: | --- |
| `CKV_AWS_289` | 4 | IAM policies must not allow permissions-management or resource-exposure actions without constraints. |
| `CKV_AWS_355` | 4 | IAM policy documents must not use `"*"` as the resource for restrictable actions. |
| `CKV_AWS_23` | 3 | Security groups and security group rules should include descriptions. |
| `CKV_AWS_288` | 3 | IAM policies must not allow unconstrained data-exfiltration permissions. |
| `CKV_AWS_290` | 3 | IAM policies must not allow unconstrained write access. |

### Highest-Leverage Fix

The highest single-resource concentration is `aws_db_instance.unencrypted_db` in `labs/lab6/vulnerable-iac/terraform/database.tf`, with 12 failed Terraform checks:

```json
{
  "resource": "aws_db_instance.unencrypted_db",
  "file_path": "/database.tf",
  "count": 12,
  "checks": [
    "CKV_AWS_161",
    "CKV_AWS_293",
    "CKV_AWS_353",
    "CKV_AWS_157",
    "CKV_AWS_129",
    "CKV_AWS_133",
    "CKV_AWS_226",
    "CKV_AWS_17",
    "CKV_AWS_118",
    "CKV_AWS_16",
    "CKV2_AWS_60",
    "CKV2_AWS_30"
  ]
}
```

The single change would be to replace that intentionally weak RDS resource with the hardened shared database pattern: encrypted storage, private access, backups, deletion protection, log exports, enhanced monitoring, Multi-AZ, auto minor upgrades, IAM database authentication, and copy-tags-to-snapshots. That is not the same as fixing twelve unrelated issues; one bad resource definition is being evaluated by twelve independent checks, so correcting the shared database definition clears the cluster at once.

### Severity Is Null

Open-source Checkov reports `severity: null` for every finding here, so I would sort a real backlog by a combination of rule frequency, resource blast radius, internet exposure, data sensitivity, and whether the resource is reused as a shared module. Paid vendor severity can save triage time, but it is still generic unless it is calibrated with environment context. A vendor label is useful input, not a substitute for knowing whether the affected resource is a production IAM policy, a public database, or a disposable lab bucket.

## Task 2

KICS commands:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/ansible/ \
  -o /path/results/kics-ansible/ --report-formats json,sarif

docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/labs/lab6":/path \
  checkmarx/kics:latest scan -p /path/vulnerable-iac/pulumi/ \
  -o /path/results/kics-pulumi/ --report-formats json,sarif
```

### Severity Breakdown

These tables count distinct KICS queries from `.queries[]`, not file-level findings.

| Ansible severity | Queries |
| --- | ---: |
| HIGH | 3 |
| LOW | 1 |

| Pulumi severity | Queries |
| --- | ---: |
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |

The terminal summaries count individual findings instead: Ansible reported 10 findings, while Pulumi reported 6 findings.

### Top Ansible Queries By Files Touched

There were only four distinct Ansible queries, so the "top five" list contains four rows.

| Files | Query | Severity |
| ---: | --- | --- |
| 6 | Passwords And Secrets - Generic Password | HIGH |
| 2 | Passwords And Secrets - Password in URL | HIGH |
| 1 | Passwords And Secrets - Generic Secret | HIGH |
| 1 | Unpinned Package Version | LOW |

### Tool Coverage Differences

KICS reported `RDS DB Instance Publicly Accessible` in the Pulumi YAML file. Checkov did not report that Pulumi finding because Checkov 3.x was used here on Terraform HCL and secrets, while KICS can parse `Pulumi-vulnerable.yaml` directly as Pulumi IaC.

Checkov reported deep Terraform IAM policy classes such as `CKV_AWS_286`, `CKV_AWS_289`, and `CKV_AWS_355`. Those came from Checkov parsing Terraform resources and embedded IAM policy JSON; the KICS scans in this lab were scoped to Ansible and Pulumi, so they did not see the Terraform IAM graph.

### Pipeline Decision

I would run both tools in CI, pinned to known versions: Checkov for Terraform and Terraform IAM-heavy review, KICS for Ansible and Pulumi. The gate should treat the union of findings as actionable, but the report should preserve the source tool and IaC format so reviewers understand why the tools disagree. For the gap between them, I would keep a small coverage matrix per IaC language and add custom policies for organization-specific rules rather than expecting one scanner to cover every format equally.

## Bonus

### Custom Policy

Policy file: `labs/lab6/policies/my-custom-policy.yaml`

```yaml
metadata:
  id: "CKV2_CUSTOM_6"
  name: "Ensure S3 buckets include a CostCenter tag"
  category: "CONVENTION"
  severity: "MEDIUM"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "tags.CostCenter"
  operator: "exists"
```

Plain English: every S3 bucket must include a `CostCenter` tag so the platform team can map storage ownership to an internal FinOps/audit control.

### Evidence That The Rule Fires

Command:

```bash
jq '[.[].results.failed_checks[]? | select(.check_id | startswith("CKV"))
     | select(.check_id | test("CUSTOM")) | {check_id, resource, file_path}]' \
  labs/lab6/results/checkov-custom/results_json.json
```

Output:

```json
[
  {
    "check_id": "CKV2_CUSTOM_6",
    "resource": "aws_s3_bucket.public_data",
    "file_path": "/main.tf"
  },
  {
    "check_id": "CKV2_CUSTOM_6",
    "resource": "aws_s3_bucket.unencrypted_data",
    "file_path": "/main.tf"
  }
]
```

### Passing Change And Confirmation

The Terraform change that makes the policy pass is to add a `CostCenter` tag to both S3 buckets, for example:

```hcl
tags = {
  Name       = "Public Data Bucket"
  CostCenter = "SEC-42"
}
```

and for the second bucket:

```hcl
tags = {
  CostCenter = "SEC-42"
}
```

I verified this on a temporary copy of the Terraform files under `/private/tmp/lab6-custom-pass` so the vulnerable lab sample stayed unchanged. After rerunning Checkov with the custom policy, the same jq filter returned:

```json
[]
```

That confirms `CKV2_CUSTOM_6` no longer appears in `failed_checks` after the tags are added.

### Why This Rule Is Custom

This is an organization-specific convention rather than a universal AWS best practice: the control comes from an internal FinOps/audit incident where untagged storage could not be mapped back to an owner or cost center during monthly cloud spend review. Checkov should ship generic security hygiene, but it cannot know that this organization routes S3 review, budget alerts, and ownership escalation through a `CostCenter` tag with values like `SEC-42`.

## Cross-PR Sanity Check

I compared the result shape with recent open Lab 6 PRs in the upstream repository, including #1724, #1715, and #1663. The core scan numbers match the common current results: Checkov `terraform 49/78`, `secrets 0/2`, KICS Ansible query breakdown `HIGH 3, LOW 1`, and KICS Pulumi query breakdown `CRITICAL 1, HIGH 2, MEDIUM 1, INFO 2`. I kept the highest-leverage section tied to our actual JSON resource grouping, where `aws_db_instance.unencrypted_db` has the largest single-resource count at 12 failed checks.
