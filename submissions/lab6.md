# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

* Checkov version: 3.3.2
* Total checks: 127
* Passed: 49
* Failed: 78
* Skipped: 0
* Resources scanned: 16

| Severity    | Count |
| ----------- | ----: |
| UNSPECIFIED |    78 |

The local Checkov JSON report did not assign severity values to the Terraform findings. Therefore, the table reports the actual value from the generated JSON rather than assigning severity levels manually.

### Top 5 rule IDs by frequency

| Rule ID     | Count | What it checks                                                                                |
| ----------- | ----: | --------------------------------------------------------------------------------------------- |
| CKV_AWS_289 |     4 | IAM policies allow permissions management or resource exposure without sufficient constraints |
| CKV_AWS_355 |     4 | IAM policy statements use `*` as the resource for restrictable actions                        |
| CKV_AWS_23  |     3 | Security groups and security-group rules must have descriptions                               |
| CKV_AWS_288 |     3 | IAM policies allow actions that may enable data exfiltration                                  |
| CKV_AWS_290 |     3 | IAM policies allow write access without sufficient constraints                                |

### Pulumi scan

KICS was used for the supplied Pulumi source because it supports Pulumi YAML directly.

| Severity  | Count |
| --------- | ----: |
| CRITICAL  |     1 |
| HIGH      |     2 |
| MEDIUM    |     1 |
| LOW       |     0 |
| INFO      |     2 |
| **Total** | **6** |

The critical Pulumi finding was a publicly accessible RDS database instance. Other findings included an unencrypted DynamoDB table, a hardcoded password, disabled EC2 detailed monitoring, disabled DynamoDB point-in-time recovery, and an EC2 instance without EBS optimization.

### Module-leverage analysis

The highest-leverage fix would be to centralize IAM policy creation in a reusable Terraform module that rejects wildcard resources and unconstrained permission-management or write actions. This change would eliminate the four `CKV_AWS_289` findings and four `CKV_AWS_355` findings, while also reducing overlapping `CKV_AWS_288` and `CKV_AWS_290` findings.

## Task 2: KICS on Ansible
### Severity breakdown

| MEDIUM    |      0 |
| LOW       |      1 |
| INFO      |      0 |

Only four unique KICS queries produced findings.
| Passwords And Secrets - Generic Password | HIGH     |              6 |
| Passwords And Secrets - Password in URL  | HIGH     |              2 |
| Passwords And Secrets - Generic Secret   | HIGH     |              1 |
| Unpinned Package Version                 | LOW      |              1 |

### Checkov vs KICS — when to use which?

Checkov performed better for the Terraform sample because it provided detailed AWS-specific resource and graph checks. It detected issues involving IAM permissions, wildcard resources, S3 configuration, RDS protection, encryption, backups, monitoring, and security-group relationships.

KICS performed better for the Ansible sample because it natively understood the playbooks and inventory files. It detected plaintext passwords, secrets in inventory variables, credentials embedded in URLs, and an unpinned package version.

The tools complement each other. Checkov provides deeper Terraform and cloud-resource analysis, while KICS supports a broader set of IaC formats, including the Ansible and Pulumi files used in this lab.

## Bonus: Custom Checkov Policy

### Policy file

```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure S3 buckets have a DataClassification tag"
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

The custom policy produced two failed checks:

```text
CKV2_CUSTOM_1 failed for aws_s3_bucket.public_data
CKV2_CUSTOM_1 failed for aws_s3_bucket.unencrypted_data

CUSTOM_COUNT=2
CUSTOM POLICY OK
```

### Why this rule matters

A `DataClassification` tag identifies the sensitivity and handling requirements of data stored in an S3 bucket. Without classification metadata, sensitive information may be stored without the correct access restrictions, encryption, retention, or monitoring controls.

This rule supports asset inventory and data-classification practices associated with the NIST Cybersecurity Framework Asset Management category. Enforcing it in CI prevents unclassified storage resources from being deployed.

| Query                                    | Severity | Files/findings |
| ---------------------------------------- | -------- | -------------: |
| **Total** | **10** |

### Top KICS queries by frequency
| Severity  |  Count |
| --------- | -----: |
| HIGH      |      9 |

