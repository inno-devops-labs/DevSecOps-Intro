# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks evaluated: 127
- Passed: 49
- Failed: 78

| Severity | Count |
|----------|------:|
| Critical | Not reported in the generated artifact |
| High | Not reported in the generated artifact |
| Medium | Not reported in the generated artifact |
| Low | Not reported in the generated artifact |

> The generated Checkov JSON report contains 49 passed and 78 failed checks for the Terraform sample. In this Checkov version, the exported JSON does not include severity fields for the failed checks, so severity counts cannot be claimed from this output.

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| `CKV_AWS_289` | 4 | Ensures IAM policies do not allow permissions management / resource exposure without constraints |
| `CKV_AWS_355` | 4 | Ensures no IAM policies documents allow `*` as a statement's resource for restrictable actions |
| `CKV_AWS_288` | 3 | Ensures IAM policies do not allow data exfiltration |
| `CKV_AWS_290` | 3 | Ensures IAM policies do not allow write access without constraints |
| `CKV_AWS_382` | 3 | Ensures no security groups allow egress from `0.0.0.0:0` to port `-1` |

### Pulumi scan
| Severity | Count |
|----------|------:|
| Critical | 1 |
| High | 2 |
| Medium | 1 |
| Low | 0 |
| Info | 2 |

> Fresh KICS output for the Pulumi sample was generated in [labs/lab6/results/kics-pulumi/results.json](labs/lab6/results/kics-pulumi/results.json), and it reported 6 findings total.

### Module-leverage analysis (Lecture 6 slide 17)
A single module-level fix would be to enforce least-privilege IAM defaults in the shared IAM module, because several failing checks revolve around overly broad role and policy permissions. In the Terraform sample, tightening the default policy document and removing wildcard actions/resources would eliminate many of the same findings at once.

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
| `Passwords And Secrets - Generic Password` | HIGH | 6 |
| `Passwords And Secrets - Generic Secret` | HIGH | 1 |
| `Passwords And Secrets - Password in URL` | HIGH | 2 |
| `Unpinned Package Version` | LOW | 1 |

### Checkov vs KICS — when to use which?
- Checkov did better for Terraform because it understands the declared AWS resources and can surface rule-based policy violations directly from the HCL structure.
- KICS did better for Ansible because it is purpose-built to scan playbooks and inventory files and it caught hardcoded secrets and configuration issues across YAML/INI content.
- A good example is the Ansible inventory secrets: Checkov is not designed for that format, while KICS flagged them directly as secret-management issues.

## Bonus: Custom Checkov Policy

### Policy file
```yaml
apiVersion: ckv2.io/v1
kind: CheckovPolicy
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure S3 buckets have lifecycle configuration
  category: GENERAL_SECURITY
  severity: HIGH
definition:
  and:
    - cond_type: resource
      resource_types:
        - aws_s3_bucket
      attribute: lifecycle_rule
      operator: exists
```

### Rule fires
```text
Verified from fresh execution: CKV2_CUSTOM_1 fired for aws_s3_bucket.public_data and aws_s3_bucket.unencrypted_data in labs/lab6/results/checkov-custom/results_json.json.
```

### Why this rule matters
Requiring an S3 lifecycle policy helps reduce storage sprawl, supports retention controls, and improves lifecycle management for data that must be retained or deleted according to policy. This is a practical governance check for compliance and cost control, especially for buckets that hold operational data.
