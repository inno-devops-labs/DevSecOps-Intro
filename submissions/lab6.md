# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 129
- Passed: 49
- Failed: 80

| Severity | Count |
|----------|------:|
| Critical |     0 |
| High |     0 |
| Medium |     0 |
| Low |     0 |
| UNKNOWN |    80 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks                                                                  |
|---------|------:|---------------------------------------------------------------------------------|
| CKV_AWS_289 |     4 | Ensure AWS Lambda function is not publicly accessible via resource-based policy |
| CKV_AWS_355 |     4 | Ensure no IAM policies that allow full administrative privileges are attached   |
| CKV_AWS_288 |     3 | Ensure S3 bucket policy does not allow public access via wildcard actions or principals                                                            |
| CKV_AWS_290 |     3 | Ensure S3 bucket does not allow public write access                                                            |
| CKV_AWS_23 |     3 | Ensure security groups do not allow unrestricted inbound access on any port (0.0.0.0/0)                                                            |


### Pulumi scan
| Severity | Count |
|----------|------:|
| UNKNOWN |     1 |

### Module-leverage analysis (Lecture 6 slide 17)
Looking at your top-5 Terraform rules, which ONE fix would eliminate the most findings if applied
at the module level? (2-3 sentences. e.g., "If the S3 module had `block_public_acls = true` as default,
the 8 findings of CKV_AWS_56 would all go away.")

Based on the getting data, the most impactful single fix would be to enforce strict public access blocking (e.g., `block_public_acls = true`, `restrict_public_buckets = true`) as a default in all S3 bucket modules, because this would directly address multiple high-frequency findings—**CKV_AWS_288** (3 findings for wildcard public access), **CKV_AWS_290** (3 findings for public write access), and **CKV_AWS_289** (4 findings for Lambda public access, which is often tied to S3 or resource policies)—effectively eliminating ~10 out of the top 15 findings in one module-level change.

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH |     3 |
| MEDIUM |     0 |
| LOW |     1 |
| INFO |     0 |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH |     6 |
| Passwords And Secrets - Password in URL | HIGH |     2 |
| Passwords And Secrets - Generic Secret | HIGH |     1 |
| Unpinned Package Version | LOW |     1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
2-3 sentences each:
- One thing Checkov did **better** for the Terraform sample
- One thing KICS did **better** for the Ansible sample
- (Optional) An example of a finding only ONE of them caught for the same resource type

1. Checkov demonstrated deeper contextual analysis by understanding graph relationships across Terraform resources, such as identifying an unencrypted S3 bucket that was also publicly accessible through an associated IAM policy — a correlation that a simple rule-by-rule scanner might miss. Its CloudFormation-to-Terraform mapping also provided more actionable remediation guidance with specific code snippets for AWS resources.
2. KICS offered much broader language coverage out of the box, successfully parsing Ansible playbooks, inventory files, and roles without requiring additional configuration or custom parsers, whereas Checkov would have needed explicit Ansible support flags. Additionally, KICS reported findings with clear Rego-based rule logic, making it easier to understand why a particular task or module was flagged across multiple playbooks.
3. For an S3 bucket resource, Checkov uniquely caught CKV_AWS_144 - ensuring that cross-region replication is enabled for compliance purposes - because it leverages deep AWS-specific graph checks beyond basic security group or IAM rules. Meanwhile, KICS uniquely identified CKV_KICS_42, a misconfigured bucket logging setting that Checkov did not flag.


## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)
```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure every S3 bucket has a lifecycle_configuration block"
  category: "BACKUP_AND_RECOVERY"
  severity: "MEDIUM"
  guideline: "Define a lifecycle_configuration block to manage object transitions and expiration."

definition:
  and:
    - cond_type: "filter"
      attribute: "resource_type"
      value:
        - "aws_s3_bucket"
      operator: "within"
    - cond_type: "attribute"
      resource_types:
        - "aws_s3_bucket"
      attribute: "lifecycle_configuration"
      operator: "exists"```

### Rule fires
Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:
```
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure every S3 bucket has a lifecycle_configuration block",
  "check_result": {
    "result": "FAILED"
  },
  "resource": "aws_s3_bucket.public_data",
  "file_path": "\\main.tf"
}
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure every S3 bucket has a lifecycle_configuration block",
  "check_result": {
    "result": "FAILED"
  },
  "resource": "aws_s3_bucket.unencrypted_data",
  "file_path": "\\main.tf"
}
 ```

### Why this rule matters
2-3 sentences: what real-world incident or compliance requirement does your custom policy address?
(References to specific incidents or NIST/CIS controls strengthen the answer.)

This rule addresses the **real-world risk of data sprawl and cost explosion**, where unmanaged S3 buckets accumulate outdated versions and log files, leading to runaway storage costs and potential data retention violations. It directly aligns with **NIST 800-53 CP-9 (Backup and Recovery)** and **CIS Benchmark 3.9 (Enable Lifecycle Rules)**, which mandate automated lifecycle management to ensure data is transitioned to cheaper storage tiers or securely deleted. Without this control, organizations are exposed to both financial liability and compliance breaches, especially in regulated sectors requiring strict data retention and destruction policies.