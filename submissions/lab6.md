# Lab 6 — IaC Security: Checkov + KICS + a Custom Policy

## Task 1: Checkov on Terraform

### Terraform scan
- Total checks: 129
- Passed: 49
- Failed: 80

### Severity breakdown
Checkov 3.3.2 does not populate the `severity` field in the JSON output for community rules — all severities returned as `null`. The findings are real; the severity metadata is omitted in the free tier. Rule descriptions and resource types were used for triage instead.

| Severity | Count |
|----------|------:|
| (not populated by Checkov CE) | 80 |

### Top 5 rule IDs by frequency
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies do not allow credentials exposure |
| CKV_AWS_355 | 4 | Ensure IAM policies limit resource scope (no wildcard Resource) |
| CKV_AWS_23 | 3 | Ensure every security group and rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies do not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies do not allow write access without constraint |

### Top 10 unique rules with descriptions
| Rule ID | Check name | Resource |
|---------|-----------|---------|
| CKV2_AWS_30 | Ensure Postgres RDS has Query Logging enabled | aws_db_instance.unencrypted_db |
| CKV2_AWS_40 | Ensure IAM policy does not allow full IAM privileges | aws_iam_policy.admin_policy |
| CKV2_AWS_5 | Ensure Security Groups are attached to another resource | aws_security_group.allow_all |
| CKV2_AWS_6 | Ensure S3 bucket has a Public Access block | aws_s3_bucket.public_data |
| CKV2_AWS_60 | Ensure RDS instance copies tags to snapshots | aws_db_instance.unencrypted_db |
| CKV2_AWS_61 | Ensure S3 bucket has a lifecycle configuration | aws_s3_bucket.public_data |
| CKV2_AWS_62 | Ensure S3 buckets have event notifications enabled | aws_s3_bucket.public_data |
| CKV_AWS_118 | Ensure enhanced monitoring is enabled for RDS | aws_db_instance.unencrypted_db |
| CKV_AWS_119 | Ensure DynamoDB Tables are encrypted using KMS CMK | aws_dynamodb_table.unencrypted_table |
| CKV_AWS_129 | Ensure RDS logs are enabled | aws_db_instance.unencrypted_db |

### Module-leverage analysis (Lecture 6 slide 17)
The highest-leverage single fix is remediating the IAM policy module: `CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, and `CKV_AWS_290` each fire 3-4 times and all target the same root cause — the `aws_iam_policy.admin_policy` resource uses wildcard `Action: "*"` and `Resource: "*"`. If the IAM module were refactored to enforce least-privilege by default (scoped actions and specific resource ARNs), those 14 combined findings would collapse to zero in a single PR. This is exactly the module-level leverage Lecture 6 slide 17 describes: fixing the policy template once closes every instance that inherits from it across all environments.

---

## Task 2: KICS on Ansible + Pulumi

### KICS Ansible scan — severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **TOTAL** | **10** |

### Top KICS Ansible queries
| Query | Severity | Findings |
|-------|----------|--------:|
| Passwords And Secrets — Generic Password | HIGH | 6 |
| Passwords And Secrets — Password in URL | HIGH | 2 |
| Passwords And Secrets — Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### KICS Pulumi scan — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **TOTAL** | **6** |

### Top KICS Pulumi queries
| Query | Severity | Findings |
|-------|----------|--------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| Passwords And Secrets — Generic Password | HIGH | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| EC2 Not EBS Optimized | INFO | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS — when to use which?

**One thing Checkov did better for the Terraform sample:**
Checkov's 2,500+ built-in policies gave much broader coverage of the Terraform AWS provider — 80 failed checks across S3, IAM, RDS, DynamoDB, and security groups with precise resource-level attribution (e.g. `aws_s3_bucket.public_data`). Its graph-based `CKV2_*` rules also caught cross-resource issues like unattached security groups (`CKV2_AWS_5`) that require understanding relationships between resources, not just individual block attributes. KICS on the same Terraform files would find fewer findings because its Rego query catalog for Terraform is smaller than Checkov's Python policy library.

**One thing KICS did better for the Ansible sample:**
KICS immediately surfaced 9 HIGH findings for hardcoded secrets across `deploy.yml`, `configure.yml`, and `inventory.ini` — including passwords embedded in database connection strings and Git repo URLs. Checkov's Ansible support is limited and would not have caught the `inventory.ini` secrets or the URL-embedded credentials. KICS's Common platform queries (CWE-798) apply across all IaC formats simultaneously, making it the better choice when your codebase mixes Ansible, Pulumi, and Terraform and you want a single secret-scanning pass across all of them.

**Finding only one tool caught:**
KICS caught `RDS DB Instance Publicly Accessible` (CRITICAL) in the Pulumi YAML file because KICS natively parses Pulumi YAML. Checkov does not have a Pulumi framework and would require a rendered state file (`pulumi preview --json`) to scan the same resource — meaning without extra setup, Checkov would have missed the publicly accessible RDS instance entirely. This is the clearest example of KICS's broader format coverage winning over Checkov's deeper policy depth.

---

## Bonus: Custom Checkov Policy

### Policy file (`labs/lab6/policies/my-custom-policy.yaml`)
```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure S3 bucket has lifecycle configuration"
  category: "GENERAL_SECURITY"
  severity: "MEDIUM"

scope:
  provider: aws

definition:
  and:
    - cond_type: "filter"
      resource_types:
        - "aws_s3_bucket"
      attribute: "resource_type"
      operator: "within"
      value:
        - "aws_s3_bucket"
    - cond_type: "connection"
      resource_types:
        - "aws_s3_bucket"
      connected_resource_types:
        - "aws_s3_bucket_lifecycle_configuration"
      operator: "exists"
```

### Rule fires
Output of Checkov with custom policy:
```
Check: CKV2_CUSTOM_1: "Ensure S3 bucket has lifecycle configuration"
  FAILED for resource: aws_s3_bucket.public_data
  File: /terraform/s3.tf
```

### Why this rule matters
S3 buckets without lifecycle policies accumulate data indefinitely, which contributed to several high-profile breaches and compliance violations where sensitive data remained accessible long after it should have been deleted or transitioned to restricted storage classes. NIST SP 800-53 control SI-12 (Information Management and Retention) and CIS AWS Foundations Benchmark 2.1.3 both require organizations to define retention and disposal policies for stored data. A custom Checkov policy enforcing lifecycle configuration ensures every S3 bucket in the infrastructure has an explicit retention decision encoded at provisioning time, preventing the "forgotten bucket" pattern that has been implicated in breaches at Capital One (2019) and numerous smaller incidents.
