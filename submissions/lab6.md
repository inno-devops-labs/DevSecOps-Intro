# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

- Total checks: 127
- Passed: 49
- Failed: 78

The local Checkov JSON output had `severity: null` for every built-in Terraform failure because no Prisma/Bridgecrew platform metadata was attached

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Prevents IAM policies from allowing permissions management or resource exposure without constraints. |
| CKV_AWS_355 | 4 | Prevents IAM policy statements from using `Resource: "*"` for restrictable actions. |
| CKV_AWS_23 | 3 | Requires descriptions on security groups and security group rules for reviewability and change control. |
| CKV_AWS_290 | 3 | Prevents IAM policies from allowing write access without limiting conditions or resources. |
| CKV_AWS_382 | 3 | Blocks security groups that allow unrestricted egress to `0.0.0.0/0` on all ports/protocols. |

### Pulumi scan
Pulumi was scanned with KICS against `labs/lab6/vulnerable-iac/pulumi`, because this lab uses KICS for native Pulumi source support. KICS found 6 Pulumi findings across public database exposure, DynamoDB encryption/recovery, EC2 monitoring, and EC2 optimization.

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Module-leverage analysis (Lecture 6 slide 17)

The highest-leverage Terraform fix is to harden the shared IAM policy module or policy-generation pattern. The two most frequent rules, `CKV_AWS_289` and `CKV_AWS_355`, both point to unconstrained IAM permissions, and fixing that centrally would also reduce related IAM findings such as `CKV_AWS_290` and `CKV_AWS_288`. A module-level rule that rejects wildcard resources, unrestricted write access, and permissions-management actions would affect `admin_policy`, `s3_full_access`, `service_policy`, and `privilege_escalation` in one place instead of treating each policy as a separate cleanup.

## Task 2: KICS on Ansible

### Severity breakdown

| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Top 5 KICS queries (by frequency)

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Unpinned Package Version | LOW | 1 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

- Checkov did better on Terraform because it produced AWS-specific checks with useful rule IDs and graph-aware relationships across resources. The IAM findings are especially useful for module-level triage because repeated failures point to one weak policy pattern rather than isolated mistakes.
- KICS did better on Ansible because it understands Ansible playbooks and also scans supporting text inputs such as `inventory.ini`. In this sample, it found credentials in inventory variables, credentials embedded in URLs, hardcoded playbook passwords, and use of `state: latest`.
- A concrete difference is Pulumi coverage: KICS scanned the Pulumi YAML source directly and reported issues such as `RDS DB Instance Publicly Accessible` and `DynamoDB Table Not Encrypted`. In this lab, Checkov was the better Terraform scanner, while KICS was the better choice for Ansible and Pulumi source coverage.

## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)

```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure S3 buckets have lifecycle configuration"
  category: "BACKUP_AND_RECOVERY"
  severity: "MEDIUM"
definition:
  and:
    - cond_type: "filter"
      attribute: "resource_type"
      value:
        - "aws_s3_bucket"
      operator: "within"
    - cond_type: "connection"
      resource_types:
        - "aws_s3_bucket"
      connected_resource_types:
        - "aws_s3_bucket_lifecycle_configuration"
      operator: "exists"
```

### Rule fires

Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:

```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 buckets have lifecycle configuration",
    "severity": "MEDIUM",
    "resource": "aws_s3_bucket.public_data",
    "file_path": "/main.tf"
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 buckets have lifecycle configuration",
    "severity": "MEDIUM",
    "resource": "aws_s3_bucket.unencrypted_data",
    "file_path": "/main.tf"
  }
]
```

### Why this rule matters

S3 lifecycle configuration makes retention, archival, and deletion behavior explicit in infrastructure code. This supports compliance expectations such as NIST SP 800-53 CP-9 for backups and AU-11 for audit record retention, because data-retention behavior is reviewed in Git instead of being configured manually after deployment. It also limits breach impact and long-term storage cost by preventing buckets from retaining stale data indefinitely.
