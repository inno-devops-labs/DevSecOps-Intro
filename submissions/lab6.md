# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Tool: Checkov 3.3.2
- Total checks: 127
- Passed: 49
- Failed: 78
- Skipped: 0
- Resources scanned: 16

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Unspecified in local Checkov JSON | 78 |

Checkov OSS did not populate the `severity` field in my local `results_json.json`, so the failed checks are reported as unspecified severity in the table above.

### Top 5 rule IDs by frequency

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies should not allow permissions management or resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policy documents should not allow `*` as the resource for restrictable actions |
| CKV_AWS_23 | 3 | Every security group and security group rule should have a description |
| CKV_AWS_288 | 3 | IAM policies should not allow data exfiltration |
| CKV_AWS_290 | 3 | IAM policies should not allow write access without constraints |

The highest-frequency Terraform findings are concentrated in `iam.tf`: `aws_iam_policy.admin_policy`, `aws_iam_role_policy.s3_full_access`, `aws_iam_user_policy.service_policy`, and `aws_iam_policy.privilege_escalation`.

### Pulumi scan

Pulumi was scanned with KICS because the lab notes that Checkov 3.x does not scan Pulumi source natively without rendered state or a different framework.

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | 6 |

Top Pulumi findings included:
- RDS DB Instance Publicly Accessible — CRITICAL
- DynamoDB Table Not Encrypted — HIGH
- Passwords And Secrets - Generic Password — HIGH
- EC2 Instance Monitoring Disabled — MEDIUM
- DynamoDB Table Point In Time Recovery Disabled — INFO

### Module-leverage analysis

The best module-level fix is to replace the permissive IAM policy pattern in `iam.tf` with least-privilege policy generation. A shared IAM policy module should reject wildcard resources for restrictable actions and require constrained actions/resources by default. That single module-level change would address the most frequent Checkov findings: CKV_AWS_289, CKV_AWS_355, CKV_AWS_288, and CKV_AWS_290 across several IAM resources.

## Task 2: KICS on Ansible + Pulumi

### Ansible severity breakdown

| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | 10 |

### Top KICS queries for Ansible

| Query | Severity | Results |
|-------|----------|--------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Pulumi severity breakdown

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | 6 |

### Top KICS queries for Pulumi

| Query | Severity | Results |
|-------|----------|--------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS — when to use which?

Checkov did better for the Terraform sample because its AWS Terraform policy coverage is broad and resource-aware. It produced many precise CKV_AWS findings and made it easy to group recurring issues by rule ID, which supports the module-level triage workflow from Lecture 6 slide 17.

KICS did better for the Ansible sample because it natively scanned playbooks and inventory files without requiring Terraform-style providers or state. It also caught secret patterns in Ansible variables, inventory values, and repository URLs, which are common operational risks in configuration-management code.

A concrete example of tool specialization is Pulumi: KICS directly scanned the Pulumi YAML source and found issues such as public RDS exposure and disabled DynamoDB encryption. Checkov was used for Terraform in this lab because Pulumi support requires a different workflow, such as rendered state or Python SAST scanning.

## Bonus: Custom Checkov Policy

### Policy file

`labs/lab6/policies/my-custom-policy.yaml`:

```yaml
metadata:
  id: CKV_CUSTOM_1
  name: "Ensure RDS instances use IAM database authentication"
  category: "IAM"
  severity: "HIGH"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_db_instance"
  attribute: "iam_database_authentication_enabled"
  operator: "equals"
  value: true
```

### Rule fires

Output of:

```bash
jq '.[0].results.failed_checks[] | select(.check_id=="CKV_CUSTOM_1") | {check_id, check_name, resource, file_path, file_line_range}' labs/lab6/results/checkov-custom/results_json.json
```

```json
{
  "check_id": "CKV_CUSTOM_1",
  "check_name": "Ensure RDS instances use IAM database authentication",
  "resource": "aws_db_instance.unencrypted_db",
  "file_path": "/database.tf",
  "file_line_range": [
    5,
    37
  ]
}
{
  "check_id": "CKV_CUSTOM_1",
  "check_name": "Ensure RDS instances use IAM database authentication",
  "resource": "aws_db_instance.weak_db",
  "file_path": "/database.tf",
  "file_line_range": [
    40,
    69
  ]
}
```

### Why this rule matters

IAM database authentication reduces long-lived static database password exposure by allowing AWS-managed IAM credentials and short-lived authentication tokens for supported RDS engines. This supports least-privilege access management and credential rotation expectations found in controls such as CIS AWS guidance and NIST SP 800-53 IA/AC control families. In real incidents, leaked database passwords often lead directly to data exposure, so removing static credential dependency is a strong preventive control.
