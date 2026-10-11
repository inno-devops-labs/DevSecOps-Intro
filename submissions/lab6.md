# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: **312**
- Passed: **248**
- Failed: **64**

| Severity | Count |
|----------|------:|
| Critical | 4 |
| High | 22 |
| Medium | 28 |
| Low | 10 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_145 | 8 | S3 bucket does not block public ACLs / public access |
| CKV_AWS_23 | 6 | Security group allows ingress from 0.0.0.0/0 |
| CKV_AWS_149 | 5 | IAM policy allows wildcard `Action` and `Resource` |
| CKV_AWS_17 | 4 | RDS instance not encrypted at rest |
| CKV_AWS_126 | 4 | RDS instance missing deletion protection |

### Pulumi scan (KICS — see Task 2)
| Severity | Count |
|----------|------:|
| HIGH | 11 |
| MEDIUM | 14 |
| LOW | 6 |
| INFO | 3 |
| **Total** | **34** |

### Module-leverage analysis (Lecture 6 slide 17)
The highest-leverage fix is a **shared S3 module defaulting `aws_s3_bucket_public_access_block` with all four flags `true`**. Eight separate `CKV_AWS_145`/`CKV_AWS_53` failures on `public_data`, `unencrypted_data`, and related buckets would collapse to zero with one module change — far more efficient than editing each bucket resource inline.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 12 |
| LOW | 7 |
| INFO | 4 |
| **Total** | **32** |

### Pulumi — severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 11 |
| MEDIUM | 14 |
| LOW | 6 |
| INFO | 3 |
| **Total** | **34** |

### Top 5 KICS queries (Ansible, by files affected)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets | HIGH | 4 |
| SSH Password Authentication Enabled | HIGH | 2 |
| Permissive File Permissions | MEDIUM | 3 |
| Command Shell Execution | MEDIUM | 2 |
| Firewall Disabled | HIGH | 1 |

### Checkov vs KICS — when to use which?
- **Checkov on Terraform:** deeper AWS graph checks (`CKV2_*` cross-resource) and huge built-in CKV catalog tuned to HCL — faster feedback loop in Terraform-only CI with SARIF native output.
- **KICS on Ansible:** Rego queries catch playbook anti-patterns (plaintext secrets, `shell:` misuse, `no_log` missing) that Checkov does not scan at all; Ansible is outside Checkov's sweet spot.
- **Example divergence:** Checkov flags `CKV_AWS_149` wildcard IAM in `iam.tf`; KICS flags Ansible inventory passwords in `inventory.ini` — same *secrets* theme, different IaC language, only one tool sees each file type.

---

## Bonus: Custom Checkov Policy

### Policy file
```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure RDS instances enable IAM database authentication
  category: DATABASE
  severity: HIGH
definition:
  cond_type: attribute
  resource_types:
    - aws_db_instance
  attribute: iam_database_authentication_enabled
  operator: equals
  value: true
```

### Rule fires
```json
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure RDS instances enable IAM database authentication",
  "file_path": "/iac/vulnerable-iac/terraform/database.tf",
  "resource": "aws_db_instance.unencrypted_db",
  "check_class": "checkov.terraform.checks.resource.aws",
  "severity": "HIGH"
}
{
  "check_id": "CKV2_CUSTOM_1",
  "file_path": "/iac/vulnerable-iac/terraform/database.tf",
  "resource": "aws_db_instance.weak_db"
}
```

### Why this rule matters
RDS instances in the sample use static passwords in Terraform (`SuperSecretPassword123!`) with no IAM DB auth — a pattern implicated in credential-spray and insider-threat scenarios. Enforcing `iam_database_authentication_enabled = true` aligns with **CIS AWS 2.3.1** (database authentication) and reduces reliance on long-lived passwords stored in state files or CI logs.
