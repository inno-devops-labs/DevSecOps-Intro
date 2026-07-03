# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan (passed/failed per framework)
| Framework  | Passed | Failed |
|------------|-------:|-------:|
| terraform  | 49     | 78     |
| secrets    | 0      | 2      |

### Top 5 rule IDs (by frequency)
| Rule ID       | Count | What it checks |
|---------------|------:|----------------|
| CKV_AWS_289   | 4     | IAM policies must not allow permissions management without constraints |
| CKV_AWS_355   | 4     | No IAM policy document allows "*" as a resource |
| CKV_AWS_23    | 3     | Every security group rule must have a description |
| CKV_AWS_288   | 3     | IAM policies must not allow data exfiltration |
| CKV_AWS_290   | 3     | IAM policies must not allow write access without constraints |

### Module-leverage analysis
Fixing the shared IAM module (scoping `Resource` and `Action`) eliminates **14 findings** (CKV_AWS_289/355/288/290). Adding descriptions to security group rules covers 3 more — **22% of failures with two module changes**.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| HIGH     | 9     |
| LOW      | 1     |

### Pulumi — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1     |
| HIGH     | 2     |
| MEDIUM   | 1     |
| INFO     | 2     |

### Top KICS queries — Ansible
| Query | Severity | Files |
|-------|----------|------:|
| Generic Password | HIGH | 6 |
| Password in URL | HIGH | 2 |
| Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS
- **Checkov** covers Terraform broadly with 2,500+ rules and graph checks.
- **KICS** natively parses Ansible/Pulumi and catches secrets/config gaps Checkov misses.
- **Unique find:** KICS found "DynamoDB Table Not Encrypted" in Pulumi; Checkov only checks key type, not absence.

---

## Bonus: Custom Checkov Policy

### Policy (`labs/lab6/policies/my-custom-policy.yaml`)
```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure S3 bucket has lifecycle configuration
  category: GENERAL_SECURITY
  severity: HIGH
definition:
  and:
    - cond_type: attribute
      resource_types:
        - aws_s3_bucket
      attribute: lifecycle_rule
      operator: exists
### Result
Both S3 buckets (`public_data`, `unencrypted_data`) flagged — **2/2 FAILED**.

### Why it matters
Prevents unlimited accumulation of old versions (cost/blast radius). Supports CIS 2.1.1 and NIST SC-28. Relevant to Capital One 2019 breach.
