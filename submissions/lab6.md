# Lab 6 - Submission

## Task 1: Checkov on Terraform

### Commands

```bash
python3 -m venv .venv
.venv/bin/pip install checkov
.venv/bin/checkov -d labs/lab6/vulnerable-iac/terraform \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-terraform/
```

Checkov version: `3.3.2`

### Terraform scan

- Total checks: 129
- Passed: 49
- Failed: 80
- Skipped: 0
- Parsing errors: 0
- Resources scanned: 18

Checkov CE produced `null` severity values for the built-in checks in this offline run, so the severity breakdown below uses the JSON value that was actually emitted.

| Severity | Count |
|----------|------:|
| Unspecified | 80 |

### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies must not allow permissions management or resource exposure without constraints. |
| CKV_AWS_355 | 4 | IAM policy documents must not use wildcard resources for restrictable actions. |
| CKV_AWS_23 | 3 | Security groups and security group rules should include descriptions. |
| CKV_AWS_288 | 3 | IAM policies must not allow data exfiltration paths. |
| CKV_AWS_290 | 3 | IAM policies must not allow unconstrained write access. |

### Module-leverage analysis

The highest-leverage fix is to replace the IAM policy construction pattern with a constrained module that requires explicit resources, explicit actions, and condition keys where possible. That would eliminate the repeated CKV_AWS_289, CKV_AWS_355, CKV_AWS_288, and CKV_AWS_290 findings from the same source: permissive IAM policies. Fixing this at the IAM module boundary is stronger than editing one inline policy because every future role/user policy would inherit least-privilege defaults.

### Pulumi scan

Pulumi was scanned with KICS as specified in Task 2, because this lab notes that Checkov 3.x does not scan Pulumi source directly without a rendered preview/state workflow.

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

Top Pulumi findings:

| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

## Task 2: KICS on Ansible + Pulumi

### Commands

```bash
docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/ansible/ \
       -o /path/results/kics-ansible/ \
       --report-formats json,sarif

docker run --rm \
  -v "$(pwd)/labs/lab6:/path" \
  checkmarx/kics:latest \
  scan -p /path/vulnerable-iac/pulumi/ \
       -o /path/results/kics-pulumi/ \
       --report-formats json,sarif
```

KICS version: `2.1.20`

### Ansible severity breakdown

| Severity | Count |
|----------|------:|
| HIGH | 3 |
| LOW | 1 |
| MEDIUM | 0 |
| INFO | 0 |

### Top KICS queries for Ansible

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS - when to use which?

Checkov did better for the Terraform sample because it produced broad AWS-specific coverage and graph-style IAM findings from a small Terraform directory. The top findings clustered around the same IAM design flaw, which makes it useful for module-level triage rather than only line-by-line remediation.

KICS did better for the Ansible sample because it natively understood the playbooks and inventory as configuration code and immediately highlighted credential exposure patterns across `deploy.yml`, `configure.yml`, and `inventory.ini`. That is the right fit for mixed IaC repositories where not everything is Terraform.

For the same broad resource class, KICS caught Pulumi YAML issues such as `RDS DB Instance Publicly Accessible` and `DynamoDB Table Not Encrypted` directly from `Pulumi-vulnerable.yaml`. Checkov's strongest output in this run came from Terraform HCL and secrets scanning, so the tools complement each other instead of replacing each other.

## Bonus: Custom Checkov Policy

### Policy file

`labs/lab6/policies/my-custom-policy.yaml`

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure S3 buckets declare an Owner tag"
  category: "GENERAL_SECURITY"
  severity: "MEDIUM"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "tags.Owner"
  operator: "exists"
```

### Rule fires

Command:

```bash
.venv/bin/checkov -d labs/lab6/vulnerable-iac/terraform \
  --external-checks-dir labs/lab6/policies \
  --output cli --output json \
  --output-file-path labs/lab6/results/checkov-custom/

jq '[.[] | .results.failed_checks[] |
  select(.check_id | startswith("CKV2_CUSTOM_")) |
  {check_id, check_name, resource, file_path, file_line_range, severity}]' \
  labs/lab6/results/checkov-custom/results_json.json
```

Output:

```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 buckets declare an Owner tag",
    "resource": "aws_s3_bucket.public_data",
    "file_path": "/main.tf",
    "file_line_range": [13, 21],
    "severity": "MEDIUM"
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 buckets declare an Owner tag",
    "resource": "aws_s3_bucket.unencrypted_data",
    "file_path": "/main.tf",
    "file_line_range": [24, 33],
    "severity": "MEDIUM"
  }
]
```

### Why this rule matters

The `Owner` tag is a lightweight but important control for accountability, incident response routing, and cloud cost ownership. CIS cloud benchmarks and most internal cloud governance programs rely on resource ownership metadata so exposed or noncompliant assets can be routed to a responsible team quickly. Without an owner, remediation delays become a process risk even when the technical finding is already known.
