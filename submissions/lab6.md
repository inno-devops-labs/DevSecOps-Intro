# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: 92 (passed + failed)
- Passed: 35
- Failed: 57

> Note: severity is intentionally blank below — the open-source edition of Checkov does **not**
> populate per-finding severity (it is a Prisma Cloud paid feature). The failed checks come back
> with `severity: null`, so instead of a severity table the meaningful breakdown for the OSS tool is
> by rule frequency (below).

| Severity | Count |
|----------|------:|
| Critical | n/a (OSS Checkov) |
| High | n/a (OSS Checkov) |
| Medium | n/a (OSS Checkov) |
| Low | n/a (OSS Checkov) |
| **Failed (total)** | 57 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure no IAM policies documents allow `"*"` as a statement's resource for restrictable actions |
| CKV_AWS_23 | 3 | Ensure every security group and rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies does not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies does not allow write access without constraints |

### Pulumi scan (via KICS — Checkov 3.x has no native Pulumi framework)
| Severity | Count |
|----------|------:|
| Critical | 1 |
| High | 2 |
| Medium | 1 |
| Low | 0 |
| Info | 2 |
| **Total** | 6 |

### Module-leverage analysis (Lecture 6 slide 17)
Four of the top-five Terraform findings — CKV_AWS_289, CKV_AWS_288, CKV_AWS_290 and CKV_AWS_355
(14 findings combined) — are the same root cause: over-permissive IAM policies that grant actions
or resources with `"*"` wildcards and no constraints. They all attach to the shared IAM policy
module, so a single module-level fix — replacing the wildcard `Action`/`Resource` with an explicit,
least-privilege list (and a condition block) in that one module — would clear all four rules at
once. That is far higher leverage than patching 14 individual resources, and it raises the
least-privilege baseline for every resource that consumes the module.

---

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | 10 |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- **Where Checkov did better (Terraform):** Checkov's 2,500-policy AWS catalog, including
  graph-based CKV2 checks, surfaced fine-grained, cloud-semantic IAM problems — e.g. distinguishing
  permissions-management vs data-exfiltration vs write wildcards (CKV_AWS_288/289/290) on a single
  policy document. That depth of provider-specific reasoning on Terraform is Checkov's strength.
- **Where KICS did better (Ansible & Pulumi):** KICS natively understands formats Checkov 3.x does
  not scan directly — it parsed the Ansible playbook and the Pulumi source out of the box via its
  Rego query engine, and was strong at secret detection (it found hardcoded passwords, passwords in
  URLs, and generic secrets in the playbook). Breadth of format coverage plus secret-hunting is
  KICS's strength; without it, the Ansible and Pulumi misconfigurations would have gone unscanned.
- **Finding only one tool caught:** KICS flagged the hardcoded database password (Passwords And
  Secrets — Generic Password, CWE-798) and the publicly-accessible RDS instance in the **Pulumi**
  source — resources Checkov simply could not scan, since it has no Pulumi framework. Conversely,
  Checkov's graph IAM checks on Terraform are more granular than KICS's equivalents.

---

## Bonus: Custom Checkov Policy

### Policy file (labs/lab6/policies/my-custom-policy.yaml)
```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure every S3 bucket carries a DataClassification tag"
  category: "GENERAL_SECURITY"
  severity: "HIGH"
definition:
  cond_type: "attribute"
  resource_types:
    - "aws_s3_bucket"
  attribute: "tags.DataClassification"
  operator: "exists"
```

### Rule fires
The custom rule `CKV2_CUSTOM_1` fired on 2 S3 buckets in the Terraform sample, both missing the
required `DataClassification` tag:

```
check_id: CKV2_CUSTOM_1  (HIGH)  FAILED
  resource: aws_s3_bucket.public_data
  file: /labs/lab6/vulnerable-iac/terraform/main.tf  (lines 13-21)
  tags present: { Name = "Public Data Bucket" }   # DataClassification missing
  evaluated_keys: tags/DataClassification

check_id: CKV2_CUSTOM_1  (HIGH)  FAILED
  resource: aws_s3_bucket.unencrypted_data
  file: /labs/lab6/vulnerable-iac/terraform/main.tf  (lines 24-33)
  tags present: (none)                             # DataClassification missing
  evaluated_keys: tags/DataClassification
```

### Why this rule matters
Mandatory data-classification tagging is a governance control that underpins almost every other
data-protection requirement: without knowing which buckets hold regulated data (PII, PCI, PHI) you
cannot scope encryption, access reviews, retention, or breach response correctly. Frameworks such as
NIST 800-53 (RA-2 security categorization) and the CIS AWS Benchmark expect resources holding
sensitive data to be identifiable, and real incidents — e.g. the 2019 Capital One breach, where a
misconfigured S3-fronting resource exposed 100M+ records — show that untracked, unclassified storage
is exactly where sensitive data leaks from. Enforcing the tag at scan time stops unclassified buckets
from ever reaching production.
