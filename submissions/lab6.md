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
| `CKV_AWS_289` | 4 | IAM policies should not allow permissions management or resource exposure without constraints |
| `CKV_AWS_355` | 4 | IAM policies should not allow `*` as a statement's resource for restrictable actions |
| `CKV_AWS_23`  | 3 | Every security group and rule must have a description |
| `CKV_AWS_288` | 3 | IAM policies should not allow data exfiltration |
| `CKV_AWS_290` | 3 | IAM policies should not allow write access without constraints |

### Module-leverage analysis (Lecture 6 slide 17)

Most of the top rules (`CKV_AWS_289`, `355`, `288`, `290`) point to the same problem: IAM policies in `iam.tf` use `"*"` for actions and resources. Instead of fixing each policy one by one, it makes more sense to create one shared IAM module with strict, limited permissions. One change at the module level would remove 14 of 78 failed checks - about 18% of all Terraform findings.

## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
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

> KICS found only 4 different query types in the Ansible scan, so the table has 4 rows instead of 5.

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

- **One thing Checkov did better for the Terraform sample:** Checkov is built for Terraform and has many ready-made AWS rules. It quickly found problems with IAM policies, security groups, and database settings - for example, wildcard permissions and missing descriptions - and gave clear rule IDs like `CKV_AWS_289` that are easy to track in CI.

- **One thing KICS did better for the Ansible sample:** KICS understands Ansible playbooks and inventory files. It found hardcoded passwords and secrets in plain text across several files, plus an unpinned package version - things Checkov does not look for because it does not scan Ansible at all.

- **Example of a finding only ONE of them caught:** KICS flagged `RDS DB Instance Publicly Accessible` (CRITICAL) in the Pulumi YAML file. Checkov did not catch this because it does not scan Pulumi source code - only Terraform in Task 1.

## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "Ensure RDS instances have storage encryption enabled"
  category: "ENCRYPTION"
  severity: HIGH

definition:
  cond_type: attribute
  resource_types:
    - aws_db_instance
  attribute: "storage_encrypted"
  operator: equals
  value: true
```

### Rule fires

Output of the B.4 jq (must show ≥1 failed check whose `check_id` starts with `CKV2_CUSTOM_`):

```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure RDS instances have storage encryption enabled",
    "check_result": {
      "result": "FAILED",
      "evaluated_keys": [
        "storage_encrypted"
      ]
    },
    "file_path": "\\database.tf",
    "resource": "aws_db_instance.unencrypted_db",
    "file_line_range": [
      5,
      37
    ],
    "severity": "HIGH"
  }
]
```

### Why this rule matters

If an RDS database is not encrypted, anyone who gets access to the disk, backup, or snapshot can read the data in plain text. This is a common real-world risk - for example, misconfigured cloud storage played a role in large data leaks like the 2019 Capital One incident. Turning on `storage_encrypted = true` matches AWS security best practices and CIS AWS Foundations Benchmark (control 2.3.1), which requires encryption for databases that store sensitive data.