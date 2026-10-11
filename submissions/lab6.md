# Lab 6 — Submission

## Task 1: Checkov on Terraform

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

All severities are `null` (Checkov 3.3.2 does not populate severity in JSON output without a Bridgecrew API key).

### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_355 | 4 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |
| CKV_AWS_289 | 4 | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| CKV_AWS_382 | 3 | Ensure no security groups allow egress from 0.0.0.0:0 to port -1 |
| CKV_AWS_290 | 3 | Ensure IAM policies does not allow write access without constraints |
| CKV_AWS_288 | 3 | Ensure IAM policies does not allow data exfiltration |

### Module-leverage analysis

Looking at the top-5 rules, all 5 involve IAM or security group policies. The single highest-leverage fix would be in the **IAM policy module**: if every IAM policy's `Statement` block used `Resource` restricted to specific ARNs (instead of `"*"`) and `Action` limited to only required API calls, that would eliminate **CKV_AWS_355**, **CKV_AWS_289**, **CKV_AWS_290**, and **CKV_AWS_288** — a total of 14 of the 78 failed checks, or ~18% of all findings from one module configuration change. Combining this with a security group module default that restricts `egress` (fixing CKV_AWS_382's 3 findings) would cover nearly 22% of all failures.

---

## Task 2: KICS on Ansible + Pulumi

### KICS on Ansible

**Scanned:** 3 files (configure.yml, deploy.yml, inventory.ini), 309 lines
**Total queries:** 287
**Total findings:** 10

#### Severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

#### Top KICS queries
| Query | Severity | Count |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### KICS on Pulumi

**Scanned:** 1 file (Pulumi-vulnerable.yaml), 280 lines
**Total queries:** 21
**Total findings:** 6

#### Severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

#### Findings
| Query | Severity | Count |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |
| EC2 Not EBS Optimized | INFO | 1 |

### Checkov vs KICS — when to use which?

**One thing Checkov did better for the Terraform sample:**
Checkov's 2,500+ built-in policies caught a wider variety of issues — from IAM wildcards (CKV_AWS_355) to S3 public access blocks (CKV_AWS_53-56) to RDS encryption (CKV_AWS_16). It scanned 127 checks across all Terraform resources and found 78 failures, covering nearly every OWASP/CSA Cloud Control Matrix category. The graph-based CKV2_ rules also caught cross-resource issues (e.g., CKV2_AWS_69 — encryption in transit across RDS instances).

**One thing KICS did better for the Ansible sample:**
KICS natively understands Ansible YAML playbooks and inventory files, which Checkov does not. It found 10 findings including hardcoded passwords in `inventory.ini` (line 5, 10, 18-20), secrets in URLs in `deploy.yml`, and unpinned package versions — all configurations Checkov would skip entirely because it lacks an Ansible platform parser. KICS also supports SARIF output, making it easier to integrate with DefectDojo (Lab 10).

**A finding only one tool caught for the same resource type:**
KICS on Pulumi found "DynamoDB Table Not Encrypted" (HIGH) on the Pulumi YAML — the DynamoDB `serverSideEncryption` attribute was missing entirely. Checkov's Terraform scan found CKV_AWS_119 ("DynamoDB Tables should be encrypted using a KMS CMK") on the Terraform DynamoDB resource, but the rule only flags the *type* of encryption key (KMS CMK vs AWS managed), not the *absence* of encryption altogether. KICS caught the more fundamental gap: no encryption at all.

---

## Bonus: Custom Checkov Policy

### Policy file

```yaml
metadata:
  id: CKV_CUSTOM_1
  name: S3 buckets must have server-side encryption configured
  category: ENCRYPTION
  severity: HIGH
definition:
  cond_type: attribute
  resource_types:
    - aws_s3_bucket
  attribute: server_side_encryption_configuration
  operator: exists
```

### Rule fires

Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV_CUSTOM"))'`:

```
CKV_CUSTOM_1 | S3 buckets must have server-side encryption configured | aws_s3_bucket.public_data | /main.tf | FAILED
CKV_CUSTOM_1 | S3 buckets must have server-side encryption configured | aws_s3_bucket.unencrypted_data | /main.tf | FAILED
```

Both S3 buckets in the vulnerable Terraform sample (`public_data` and `unencrypted_data`) lack a `server_side_encryption_configuration` block and are flagged by the custom policy — 2 FAILED out of 2 matching resources.

### Why this rule matters

AWS S3 buckets without server-side encryption expose data at rest to unauthorized physical access to disk or snapshot exports. The **Capital One breach (2019)** exploited a misconfigured S3 bucket that stored unencrypted customer data, affecting 100+ million users. This rule directly enforces **NIST SP 800-53 SC-28** (Protection of Information at Rest) and **CIS AWS Foundations Benchmark 2.1.1** ("Ensure S3 buckets are encrypted at rest"), and would have prevented data exposure in numerous real-world incidents where encryption was simply forgotten during bucket creation.