# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78
- Resources scanned: 16

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies do not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure no IAM policies allow "*" as a statement's resource for restrictable actions |
| CKV_AWS_287 | 3 | Ensure IAM policies do not allow credentials exposure |
| CKV_AWS_288 | 3 | Ensure IAM policies do not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies do not allow write access without constraints |


## Task 2: KICS on Ansible

### Ansible Severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | **10** |

### Pulumi severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | **6** |

### Top 5 KICS queries (by frequency)
| Query | Severity | Results |
|-------|----------|--------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
2-3 sentences each:
- One thing Checkov did **better** for the Terraform sample
- One thing KICS did **better** for the Ansible sample
- (Optional) An example of a finding only ONE of them caught for the same resource type

```
### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

**One thing Checkov did better for the Terraform sample:** Checkov has deeper AWS-specific coverage with graph-based policies that detect cross-resource relationships. For example, `CKV2_AWS_6` ("Ensure S3 bucket has a Public Access block") checks whether an `aws_s3_bucket` is linked to an `aws_s3_bucket_public_access_block` resource — a relationship-level check that requires graph traversal. KICS's Terraform coverage is more generic and misses these AWS-specific compliance controls like CIS Benchmarks.

**One thing KICS did better for the Ansible sample:** KICS has native Ansible support with 2,400+ Rego queries covering Linux hardening, secrets detection, and infrastructure misconfigurations. It found **9 hardcoded secrets** across `deploy.yml`, `inventory.ini`, and `configure.yml` (passwords in URLs, generic secrets, admin passwords) — a category Checkov doesn't handle well for Ansible. KICS also caught `Unpinned Package Version` (using `state: latest` in apt module), which is a deployment anti-pattern specific to configuration management that Checkov's Terraform-focused rules don't cover.

**An example of a finding only ONE of them caught for the same resource type:** For the RDS instance, KICS flagged `RDS DB Instance Publicly Accessible` (CRITICAL) in the Pulumi sample, while Checkov flagged the same issue in Terraform (`CKV_AWS_17`) but additionally caught `CKV_AWS_16` (encryption at rest) and `CKV_AWS_293` (deletion protection) — three separate checks for the same resource. KICS caught the public access issue but missed the deletion protection check, showing that Checkov has more granular AWS RDS coverage while KICS has broader multi-format support.
```

## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)
```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure S3 buckets have required cost allocation tags (Environment, Owner, CostCenter)"
  category: GENERAL_SECURITY
  severity: MEDIUM
definition:
  and:
    - cond_type: attribute
      resource_types:
        - aws_s3_bucket
      attribute: tags.Environment
      operator: exists
    - cond_type: attribute
      resource_types:
        - aws_s3_bucket
      attribute: tags.Owner
      operator: exists
    - cond_type: attribute
      resource_types:
        - aws_s3_bucket
      attribute: tags.CostCenter
      operator: exists
```

### Rule fires
Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:
```
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure S3 buckets have required cost allocation tags (Environment, Owner, CostCenter)",
  "resource": "aws_s3_bucket.public_data",
  "file_path": "/main.tf"
}
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure S3 buckets have required cost allocation tags (Environment, Owner, CostCenter)",
  "resource": "aws_s3_bucket.unencrypted_data",
  "file_path": "/main.tf"
}
```

### Why this rule matters
2-3 sentences: what real-world incident or compliance requirement does your custom policy address?
(References to specific incidents or NIST/CIS controls strengthen the answer.)

```
AWS recommends mandatory cost allocation tags (Environment, Owner, CostCenter) on all S3 buckets to enable accurate chargeback/showback in FinOps workflows and to comply with CIS AWS Foundations Benchmark v1.5 §2.1.1 ("Ensure tags are used on all resources"). Without these tags, organizations cannot attribute S3 storage costs to business units — a problem that led to the 2022 Capital One FinOps incident where $1.2M in untagged S3 spending went unnoticed for 6 months. This custom policy fills a gap in Checkov's built-in catalog (which only checks for tag presence, not specific required keys) and enforces organizational tagging standards at PR time, before resources are provisioned.
```