# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

- Total checks: 127
- Passed: 49
- Failed: 78
- Skipped: 0
- Resource count: 16
- Checkov version: 3.3.2

| Severity | Count |
|----------|------:|
| Unspecified / null | 78 |

### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensures IAM policies do not allow permissions management or resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensures IAM policy documents do not allow `"*"` as a resource for restrictable actions |
| CKV_AWS_23 | 3 | Ensures every security group and rule has a description |
| CKV_AWS_288 | 3 | Ensures IAM policies do not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensures IAM policies do not allow write access without constraints |

### Pulumi scan

Pulumi was scanned with KICS because the lab instructions explain that Checkov 3.x does not directly scan Pulumi source as a Pulumi framework in the same way it scans Terraform.

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Module-leverage analysis

The highest-leverage fix would be at the IAM policy module level. Several top findings come from overly broad IAM policies, especially wildcard resources, unrestricted write access, data exfiltration permissions, and permissions-management exposure. If the IAM module generated least-privilege policies by default and avoided `"Action": "*"` / `"Resource": "*"`, it would remove many repeated findings across `aws_iam_policy.admin_policy`, `aws_iam_role_policy.s3_full_access`, `aws_iam_user_policy.service_policy`, and `aws_iam_policy.privilege_escalation`.

## Task 2: KICS on Ansible

### Severity breakdown

| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Top 5 KICS queries (by frequency)

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### KICS on Pulumi

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Top 5 KICS Pulumi queries

| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS — when to use which?

Checkov did better for the Terraform sample because it produced many AWS/Terraform-specific findings and grouped repeated IAM, S3, RDS, and security group misconfigurations by Checkov rule ID. This makes it easier to triage at the module level, because repeated rules such as `CKV_AWS_289`, `CKV_AWS_355`, and `CKV_AWS_23` show which reusable modules should be fixed first.

KICS did better for the Ansible sample because it directly scanned Ansible playbooks and inventory files and detected problems such as hardcoded passwords, secrets in URLs, and unpinned package versions. These are practical configuration-management issues that are not the main focus of Terraform-only Checkov scanning.

A concrete example is the Ansible inventory and playbook secrets. KICS found multiple password and secret findings in `inventory.ini`, `configure.yml`, and `deploy.yml`, while the Terraform Checkov scan focused on cloud resource misconfigurations such as IAM wildcard permissions, public security groups, and unencrypted storage.

## Bonus: Custom Checkov Policy

### Policy file

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure S3 buckets have Project tag set to lab6"
  category: "GENERAL_SECURITY"
  severity: "MEDIUM"

definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "tags.Project"
  operator: "equals"
  value: "lab6"
```

### Rule fires

Output of:

```bash
jq '.[0].results.failed_checks[]
| select(.check_id | startswith("CKV2_CUSTOM_"))' \
labs/lab6/results/checkov-custom/results_json.json
```

The custom rule fired on two S3 buckets:

```text
CKV2_CUSTOM_1 FAILED aws_s3_bucket.public_data
CKV2_CUSTOM_1 FAILED aws_s3_bucket.unencrypted_data
```

Relevant output excerpt:

```text
check_id: CKV2_CUSTOM_1
check_name: Ensure S3 buckets have Project tag set to lab6
result: FAILED
resource: aws_s3_bucket.public_data
file_path: /main.tf
evaluated_keys:
  - tags/Project
severity: MEDIUM
```

```text
check_id: CKV2_CUSTOM_1
check_name: Ensure S3 buckets have Project tag set to lab6
result: FAILED
resource: aws_s3_bucket.unencrypted_data
file_path: /main.tf
evaluated_keys:
  - tags/Project
severity: MEDIUM
```

### Why this rule matters

Requiring a project tag on S3 buckets helps with ownership, auditability, cost allocation, and incident response. If an exposed or misconfigured bucket is discovered, tags make it easier to identify which project owns the resource and who should fix it. This supports asset management and accountability practices similar to CIS and NIST-style security inventory controls, where cloud resources should be identifiable and traceable to an owner or project.
