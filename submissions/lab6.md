# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

| Severity | Count |
|----------|------:|
| Unknown  | 78 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensures IAM policies do not allow permission management/resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensures IAM policies do not allow unrestricted resource access ('*') for restricted actions |
| CKV_AWS_23  | 3 | Ensures every Security Group rule has a description |
| CKV_AWS_288 | 3 | Ensures IAM policies do not permit data exfiltration |
| CKV_AWS_290 | 3 | Ensures IAM policies do not allow write access without constraints |

### Pulumi scan
| Severity | Count |
|----------|------:|
| CRITICAL | 1     |
| HIGH     | 2     |
| MEDIUM   | 1     |
| INFO     | 2     |

### Module-leverage analysis (Lecture 6 slide 17)
Looking at the top-5 Terraform rules, fixing the root IAM policy module to drop overly permissive actions (such as `Action: *` or removing full admin/write access constraints) would eliminate the majority of the highest-frequency findings (`CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, and `CKV_AWS_290`) all at once. By enforcing strict least-privilege constraints centrally at the IAM module level, we can resolve 14 separate findings with a single architectural update.

---

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH     | 9     |
| MEDIUM   | 0     |
| LOW      | 1     |
| INFO     | 0     |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- Checkov performs exceptionally well with Terraform because its graph-based evaluation (CKV2) accurately maps dependencies and resource relationships. 
- KICS shines with Ansible because its Rego-based queries are highly flexible and broadly support configuration management files, whereas Checkov's support for non-cloud-native IaC is more limited. 

---

## Bonus: Custom Checkov Policy

### Policy file
```yaml
metadata:
  name: "Ensure all S3 buckets have versioning enabled"
  id: "CKV2_CUSTOM_1"
  category: "BACKUP_AND_RECOVERY"
  severity: "HIGH"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "versioning.enabled"
  operator: "equals"
  value: true
```

### Rule fires
Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:
```json
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure all S3 buckets have versioning enabled",
  "resource": "aws_s3_bucket.public_data"
}
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure all S3 buckets have versioning enabled",
  "resource": "aws_s3_bucket.unencrypted_data"
}
```

### Why this rule matters
This rule addresses the critical need for data resilience and ransomware protection. Enabling S3 bucket versioning ensures that if data is maliciously modified or accidentally deleted, previous versions can be seamlessly recovered, which directly aligns with CIS and NIST frameworks for incident recovery.
