# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan (passed/failed per framework)
| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 49 | 78 |
| secrets | 0 | 2 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies allow overly permissive privilege management |
| CKV_AWS_355 | 4 | IAM policies allow '*' as a resource for risky actions |
| CKV_AWS_23  | 3 | IAM role lacks an attached permissions boundary |
| CKV_AWS_288 | 3 | IAM policies allow potential data exfiltration |
| CKV_AWS_290 | 3 | IAM policies allow privilege escalation |

### Module-leverage analysis (Lecture 6 slide 17)
All top 5 failed checks (accounting for 17 total findings) are strictly related to overly permissive AWS IAM configurations. If we transition to using a centralized, hardened IAM Terraform module that automatically enforces a strict `permissions_boundary` (CKV_AWS_23) and explicitly denies the use of `Resource: "*"` (CKV_AWS_355), we would eliminate all of these high-risk findings across the entire infrastructure with a single architectural update.

## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Pulumi — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Top 5 KICS queries — Ansible (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- **One thing Checkov did better for the Terraform sample:** Checkov handles cloud-native resource relationships exceptionally well by evaluating structural dependency graphs, allowing it to efficiently map complex misconfigurations across interconnected elements like AWS IAM policies and permission boundaries.
- **One thing KICS did better for the Ansible sample:** KICS is far more effective at scanning step-by-step operational playbooks and configuration scripts, parsing line-by-line automation rules to catch embedded syntax errors and hardcoded variables.
- **An example of a finding only ONE of them caught for the same resource type:** KICS successfully triggered highly specific secret-detection patterns, exposing critical entries such as plaintext hardcoded passwords and exposed credentials inside URLs within the Ansible deployment files that generic IaC properties-checkers overlooked.

## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)
```yaml
metadata:
  name: "Ensure S3 bucket has versioning enabled"
  id: "CKV_CUSTOM_1"
  category: "BACKUP_AND_RECOVERY"
  severity: "MEDIUM"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "versioning/enabled"
  operator: "equals"
  value: true

```

### Rule fires
Output of the B.4 jq (must show ≥1 failed check whose `check_id` starts with `CKV2_CUSTOM_`):
```
{
  "check_id": "CKV_CUSTOM_1",
  "check_name": "Ensure S3 bucket has versioning enabled",
  "check_result": {
    "result": "FAILED",
    "evaluated_keys": [
      "versioning/enabled"
    ]
  },
  "resource": "aws_s3_bucket.public_data",
  "severity": "MEDIUM",
  "file_path": "/main.tf",
  "file_line_range": [
    13,
    21
  ]
}
{
  "check_id": "CKV_CUSTOM_1",
  "check_name": "Ensure S3 bucket has versioning enabled",
  "check_result": {
    "result": "FAILED",
    "evaluated_keys": [
      "versioning/enabled"
    ]
  },
  "resource": "aws_s3_bucket.unencrypted_data",
  "severity": "MEDIUM",
  "file_path": "/main.tf",
  "file_line_range": [
    24,
    33
  ]
}
```
(Note: JSON output has been truncated for brevity to show the exact failing resources and rule ID matching the custom policy).

### Why this rule matters
Enforcing S3 versioning is a critical defense mechanism against accidental data deletion and ransomware attacks, where malicious actors might overwrite or destroy cloud objects. This custom policy directly maps to data protection standards like the CIS AWS Foundations Benchmark, which mandates robust backup and recovery controls. By implementing this as Policy-as-Code, we guarantee that every deployed bucket inherently supports point-in-time recovery without relying on manual reviews.
