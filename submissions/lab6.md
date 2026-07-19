# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

| Severity | Count |
|----------|------:|
| Critical | N/A |
| High | N/A |
| Medium | N/A |
| Low | N/A |
| Unknown / not populated in local OSS JSON | 78 |

The local Checkov OSS JSON output for this run did not populate `severity` on failed Terraform checks, so a standard Critical/High/Medium/Low breakdown was not available in this environment. I kept the counts exactly aligned with the actual report instead of inferring severities manually.

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| `CKV_AWS_289` | 4 | Ensure IAM policies do not allow permissions management or resource exposure without constraints |
| `CKV_AWS_355` | 4 | Ensure IAM policy documents do not allow `Resource: "*"` for restrictable actions |
| `CKV_AWS_288` | 3 | Ensure IAM policies do not allow data exfiltration |
| `CKV_AWS_290` | 3 | Ensure IAM policies do not allow write access without constraints |
| `CKV_AWS_23` | 3 | Ensure every security group and rule has a description |

### Pulumi note
Per the lab instructions, I did not use Checkov directly on Pulumi source. The lab note explains that Pulumi is scanned with KICS in this exercise because KICS natively understands the provided Pulumi YAML format, while Checkov is focused here on Terraform.

### Module-leverage analysis (Lecture 6 slide 17)
The single highest-leverage fix would be tightening the IAM policy module to ban wildcard permissions and unrestricted resources by default. That one design change would cut across the top repeated findings at once, including `CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, and `CKV_AWS_290`, instead of fixing each individual policy by hand.

## Task 2: KICS on Ansible + Pulumi

### Ansible severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total queries** | 4 |

### Top KICS queries on Ansible (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| `Passwords And Secrets - Generic Password` | HIGH | 6 |
| `Passwords And Secrets - Password in URL` | HIGH | 2 |
| `Passwords And Secrets - Generic Secret` | HIGH | 1 |
| `Unpinned Package Version` | LOW | 1 |

### Pulumi severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total queries** | 6 |

### Top KICS queries on Pulumi (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| `RDS DB Instance Publicly Accessible` | CRITICAL | 1 |
| `DynamoDB Table Not Encrypted` | HIGH | 1 |
| `Passwords And Secrets - Generic Password` | HIGH | 1 |
| `EC2 Instance Monitoring Disabled` | MEDIUM | 1 |
| `DynamoDB Table Point In Time Recovery Disabled` | INFO | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- One thing Checkov did better for the Terraform sample: it gave much deeper Terraform-specific coverage for AWS resources, especially on IAM and infrastructure relationships. The repeated `CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, and `CKV_AWS_290` findings showed strong policy granularity around overly broad IAM permissions that is very useful for module-level remediation.
- One thing KICS did better for the Ansible sample: it handled configuration-management and secrets patterns directly in playbooks, including generic passwords, secrets, and credentials embedded in URLs. That is a better fit for Ansible content than a Terraform-focused scanner, and it also worked natively on the provided Pulumi YAML.
- An example of a finding only one of them caught for the same broad problem space: KICS flagged `Passwords And Secrets - Password in URL` in the Ansible sample, which is a configuration/content-pattern issue rather than a cloud-resource policy issue. On the other hand, Checkov surfaced multiple Terraform-specific IAM governance findings that KICS was not being used to model here at the same level of detail.

## Bonus: Custom Checkov Policy

### Policy file (`labs/lab6/policies/my-custom-policy.yaml`)
```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure S3 buckets define at least one lifecycle rule"
  category: "BACKUP_AND_RECOVERY"
  guideline: "Require lifecycle management on S3 buckets to support retention, archival, and cleanup controls."
  severity: "MEDIUM"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "lifecycle_rule"
  operator: "exists"
```

### Rule fires
Output summary:

```text
count 2
CKV2_CUSTOM_1 | Ensure S3 buckets define at least one lifecycle rule | aws_s3_bucket.public_data | /main.tf [13, 21]
CKV2_CUSTOM_1 | Ensure S3 buckets define at least one lifecycle rule | aws_s3_bucket.unencrypted_data | /main.tf [24, 33]
```

### Why this rule matters
Lifecycle rules are a practical control for retention, cleanup, and cost-aware data governance on object storage. In real environments they support backup-and-recovery discipline, reduce the risk of stale sensitive data lingering indefinitely, and help align storage handling with retention expectations from internal policy or controls such as NIST-style data lifecycle management practices.
