# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

- Checkov version: 3.3.2
- Total checks: 127
- Passed: 49
- Failed: 78
- Skipped: 0
- Resources scanned: 16

| Severity    | Count |
| ----------- | ----: |
| UNSPECIFIED |    78 |

The Terraform scan results come from Checkov JSON output, which in this environment does not explicitly map severities to built-in rules. Therefore, severity is reported as UNSPECIFIED rather than inferred.

### Top 5 rule IDs by frequency

| Rule ID     | Count | What it checks |
|-------------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies allow permission management or overly broad resource exposure |
| CKV_AWS_355 | 4 | IAM policies use wildcard `*` as resource in restricted actions |
| CKV_AWS_23  | 3 | Security groups and rules must include descriptions |
| CKV_AWS_288 | 3 | IAM policies may allow data exfiltration paths |
| CKV_AWS_290 | 3 | IAM policies allow unrestricted write access |

### Module-leverage analysis (Lecture 6 slide 17)

The highest-leverage fix is standardizing IAM policy creation inside a reusable Terraform module. Most findings originate from overly permissive IAM definitions, especially wildcard resources and unrestricted actions.

If the IAM module enforced least-privilege defaults (no `"*"`, explicit allowed actions, and constrained resources), it would eliminate all occurrences of CKV_AWS_289 and CKV_AWS_355 and significantly reduce CKV_AWS_288 and CKV_AWS_290 as well.

Fixing this at module level is more effective than patching individual resources because it prevents repeated misconfigurations across multiple roles and policies.

---

### Pulumi scan

Pulumi was analyzed using KICS because it supports the provided Pulumi YAML/definition format.

| Severity  | Count |
|-----------|------:|
| CRITICAL  | 1 |
| HIGH      | 2 |
| MEDIUM    | 1 |
| LOW       | 0 |
| INFO      | 2 |
| **Total** | **6** |

Top findings:

| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

---

## Task 2: KICS on Ansible + Pulumi

### KICS severity breakdown (Ansible)

| Severity | Count |
|----------|------:|
| HIGH     | 9 |
| LOW      | 1 |
| MEDIUM   | 0 |
| INFO     | 0 |

### Top KICS queries (Ansible)

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

---

### Checkov vs KICS — comparison

Checkov performs better on Terraform because it provides structured, rule-based analysis of AWS infrastructure with consistent rule IDs (CKV_AWS_*). This makes it especially strong for identifying repeated misconfigurations such as IAM policy issues and security group misconfigurations.

KICS performs better on Ansible because it directly understands playbooks and inventory files. It is more effective at detecting secrets in configuration files, such as hardcoded credentials, passwords in URLs, and unpinned dependencies.

For Pulumi, KICS also provides useful coverage by detecting misconfigurations like public RDS exposure and missing encryption, which complements Checkov’s Terraform-focused analysis.

Overall, the tools are complementary: Checkov is stronger for Terraform-centric policy enforcement, while KICS provides broader IaC coverage across Ansible and Pulumi.

---

## Bonus: Custom Checkov Policy

### Policy file

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure S3 buckets define a DataClassification tag"
  category: "CONVENTION"
  severity: "MEDIUM"

definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "tags.DataClassification"
  operator: "exists"
```

### Rule fires

The custom rule successfully detected missing classification tags:

```
CKV2_CUSTOM_1 failed for aws_s3_bucket.public_data
CKV2_CUSTOM_1 failed for aws_s3_bucket.unencrypted_data

CUSTOM_COUNT=2
```

### Why this rule matters

A DataClassification tag is required to classify the sensitivity level of stored data. This enables proper enforcement of security controls such as encryption, access restrictions, and retention policies. Without classification metadata, resources may be mismanaged or under-protected. This aligns with common enterprise security governance and NIST-style asset management principles.