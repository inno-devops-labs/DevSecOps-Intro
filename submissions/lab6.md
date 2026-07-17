# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Unknown | 78 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |
| CKV_AWS_23 | 3 | Ensure every security group and rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies does not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies does not allow write access without constraints |

### Pulumi scan
| Severity | Count |
|----------|------:|
| Critical | 1 |
| High | 2 |
| Medium | 1 |
| Low | 0 |
| Info | 2 |

### Module-leverage analysis (Lecture 6 slide 17)
The top rule (CKV_AWS_289) appears 4 times. If the IAM policy module was updated to use constrained resources instead of wildcards, it would eliminate all 4 findings of this rule across the project.

---

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- Checkov provided more comprehensive checks for the Terraform infrastructure, especially regarding IAM policies and security group descriptions.
- KICS was better for the Ansible sample as it natively understands Ansible playbooks and successfully identified hardcoded secrets and unpinned package versions.
- For the same resource type (e.g., Secrets), KICS used generic "Passwords and Secrets" queries that worked across both Ansible and Pulumi, whereas Checkov had specific secret scanners.

---

## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)
```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure S3 buckets have a lifecycle configuration
  category: STORAGE
  severity: MEDIUM
definition:
  and:
    - cond_type: attribute
      attribute: lifecycle_rule
      operator: exists
```

### Rule fires
Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:
```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 buckets have a lifecycle configuration",
    ...
  }
]
```

### Why this rule matters
Ensuring S3 buckets have a lifecycle configuration is critical for cost management and compliance (e.g., GDPR/HIPAA) by automatically deleting old data or moving it to cheaper storage classes after a certain period.
