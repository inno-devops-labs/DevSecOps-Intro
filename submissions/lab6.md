# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Resources scanned: 16
- Terraform framework: 49 passed / 78 failed
- Secrets framework: 0 passed / 2 failed (hardcoded AWS credentials)
- **Total failed: 80**

### Severity
Checkov Community Edition does not populate per-finding severity — all 80 failed checks report `severity: null` (severity metadata ships only in the paid Prisma/Bridgecrew platform). So instead of a severity table I triage by **rule frequency** below, which is the leverage signal Lecture 6 slide 17 actually recommends.

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies must not allow permissions-management / resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policy documents must not use `"*"` as a statement resource for restrictable actions |
| CKV_AWS_23 | 3 | Every security group and rule must have a description |
| CKV_AWS_288 | 3 | IAM policies must not allow data exfiltration |
| CKV_AWS_290 | 3 | IAM policies must not allow write access without constraints |

### Module-leverage analysis (Lecture 6 slide 17)
Four of the top five rules (CKV_AWS_288, 289, 290, 355 — 14 findings combined) are all the *same root cause*: IAM policies written with wildcard `"*"` actions and resources. The single highest-leverage fix is to rewrite the shared IAM policy document so that `Action` and `Resource` are scoped to specific ARNs and a least-privilege action list instead of `"*"`. Because the vulnerable Terraform reuses one over-permissive policy pattern across multiple roles/users, replacing that one pattern at the module level clears all four rules at once — far more efficient than patching each resource individually. The remaining frequent rule (CKV_AWS_23, missing security-group descriptions) is cosmetic by comparison and lower priority.

### Pulumi scan (Checkov)
Running Checkov on the Pulumi directory returned only **1 finding** — `CKV_SECRET_6` (Base64 High Entropy String: a hardcoded `apiKey` in `Pulumi-vulnerable.yaml:19`), via the secrets framework.

| Severity | Count |
|----------|------:|
| (CE: null) | 1 |

Checkov has **no native Pulumi framework** — it understands Terraform/HCL deeply but treats Pulumi's Python (`__main__.py`) as plain source, so it cannot reason about the 20+ Pulumi IaC misconfigurations (public S3, wildcard IAM, unencrypted RDS, etc.) the way it does for Terraform. The only thing it caught was a literal secret string, which its generic secrets scanner flags in any file type. This is exactly why the lab routes Pulumi to **KICS in Task 2** — KICS has first-class Pulumi support and surfaces the actual resource misconfigurations. It's a concrete demonstration of tool-ecosystem specialization: the right scanner depends on the IaC language, not just the cloud.

## Task 2: KICS on Ansible + Pulumi

### KICS on Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | 10 |

### Top KICS queries — Ansible (by frequency)
| Query | Severity | Results |
|-------|----------|--------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### KICS on Pulumi — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | 6 |

### Top KICS queries — Pulumi
| Query | Severity | Results |
|-------|----------|--------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| EC2 Not EBS Optimized / DynamoDB PITR Disabled | INFO | 2 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)
- **Checkov did better on the Terraform sample.** It produced 80 findings across 16 resources with deep, rule-specific coverage (IAM wildcard analysis, RDS/S3/SG misconfigurations), each mapped to a precise CKV_AWS_* ID. Checkov's HCL graph engine understands Terraform resource relationships, so it caught far more real misconfigurations on Terraform than a generic scanner would.
- **KICS did better on the Ansible sample.** Checkov has no real Ansible coverage, whereas KICS shipped dedicated Ansible queries and immediately surfaced 10 findings — including the hardcoded passwords across `deploy.yml` and `inventory.ini` and the unpinned-package-version risk. For Ansible, KICS is simply the tool that has the queries.
- **Same resource type, different tool — Pulumi is the clearest example.** On the identical Pulumi sample, Checkov found only **1** issue (a hardcoded secret via its generic secrets scanner) because it has no native Pulumi framework, while KICS found **6**, including a **CRITICAL** publicly-accessible RDS instance and an unencrypted DynamoDB table — genuine resource misconfigurations Checkov was blind to. The lesson: tool choice must follow the IaC language, not just the cloud provider — Checkov for Terraform/HCL, KICS for Pulumi and Ansible.

## Bonus: Custom Checkov Policy

### Policy file (labs/lab6/policies/my-custom-policy.yaml)

    metadata:
      id: "CKV2_CUSTOM_1"
      name: "Ensure all RDS DB instances have storage encryption enabled"
      category: "ENCRYPTION"
      severity: "HIGH"
    definition:
      cond_type: "attribute"
      resource_types:
        - "aws_db_instance"
      attribute: "storage_encrypted"
      operator: "equals"
      value: true

### Rule fires
Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:

    [
      {
        "check_id": "CKV2_CUSTOM_1",
        "resource": "aws_db_instance.unencrypted_db",
        "file": "\\database.tf"
      }
    ]

The policy was loaded via `--external-checks-dir labs/lab6/policies` and fired on `aws_db_instance.unencrypted_db`, which sets `storage_encrypted = false` in `database.tf`.

### Why this rule matters
Unencrypted RDS storage means the database's data-at-rest — including the PostgreSQL contents and any backups/snapshots — sits in plaintext on the underlying EBS volumes. If an attacker or insider gains access to the storage layer, or a snapshot is shared/leaked, the data is readable with no further effort. This maps directly to **CIS AWS Foundations Benchmark** controls requiring encryption at rest and to **PCI-DSS Requirement 3** (protect stored cardholder data). The 2019 Capital One breach is a well-known reminder of how exposed AWS data stores turn a single misconfiguration into a mass data leak. Enforcing `storage_encrypted = true` as a hard gate in CI ensures no RDS instance ships without encryption, regardless of which engineer writes the Terraform — exactly the org-specific guardrail that custom Policy-as-Code provides on top of vendor defaults.