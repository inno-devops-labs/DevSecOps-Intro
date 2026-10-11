# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks: **127** (49 passed + 78 failed per `summary`)
- Passed: **49**
- Failed: **78** (80 failed check instances across resources)

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 25 |
| Medium | 50 |
| Low | 5 |

*(Checkov 3.3.2 JSON omits `severity` on built-in checks; counts classified from `check_name` / rule metadata.)*

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies must not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policy documents must not allow `"*"` as resource for restrictable actions |
| CKV_AWS_23 | 3 | Every security group and rule must have a description |
| CKV_AWS_288 | 3 | IAM policies must not allow data exfiltration |
| CKV_AWS_290 | 3 | IAM policies must not allow unconstrained write access |

### Pulumi scan (Checkov secrets on YAML)
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| **Failed (secrets)** | **1** (`CKV_SECRET_6` — Base64 High Entropy String in `Pulumi-vulnerable.yaml`) |

> Per lab notes, Pulumi **infrastructure** misconfigs are scanned with KICS (Task 2); Checkov natively flags the hardcoded API key via its secrets framework.

### Module-leverage analysis (Lecture 6 slide 17)
The highest-leverage single fix is tightening the **IAM policy module** to forbid `Action: "*"` and `Resource: "*"` (and scoped variants). Rules **CKV_AWS_355** (4×), **CKV_AWS_289** (4×), **CKV_AWS_288** (3×), and **CKV_AWS_290** (3×) all fire on the same wildcard IAM anti-pattern — **14 findings** from one module-level policy guardrail instead of patching each inline policy individually.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown
| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total queries** | **10** |

### Ansible — top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Pulumi (KICS) — severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | **6** |

### Pulumi — top queries
| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

- **Checkov did better on Terraform** because its **graph checks (CKV2_*)** trace relationships across resources (e.g., S3 bucket ↔ public access block ↔ IAM role attachments). KICS Terraform coverage is thinner; our Terraform run surfaced 78 failures with deep IAM graph analysis.
- **KICS did better on Ansible** because Rego queries target playbook idioms directly — hardcoded passwords in `vars`, `shell:` without `no_log`, credentials in inventory URLs — which Checkov does not scan at all.
- **Finding only one tool caught:** Checkov's **IAM graph rules** (CKV_AWS_355 on wildcard `Resource: *`) have no Ansible equivalent; conversely KICS flagged **Password in URL** in `deploy.yml` git clone strings — a pattern Checkov's Terraform-focused engine never sees.

---

## Bonus: Custom Checkov Policy

### Policy file (full contents of `labs/lab6/policies/my-custom-policy.yaml`)
```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure RDS instances enable IAM database authentication
  category: DATABASE_CONFIGURATION
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
```
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure RDS instances enable IAM database authentication",
  "resource": "aws_db_instance.unencrypted_db",
  "severity": "HIGH"
}
{
  "check_id": "CKV2_CUSTOM_1",
  "resource": "aws_db_instance.weak_db",
  "severity": "HIGH"
}
```
(2 RDS instances failed — neither sets `iam_database_authentication_enabled = true`.)

### Why this rule matters
IAM database authentication lets applications obtain short-lived RDS auth tokens instead of static passwords in connection strings — reducing credential theft blast radius. This aligns with **CIS AWS Benchmark** database access controls and prevents scenarios like leaked Terraform `password = "..."` values (present in our `database.tf`) from becoming long-lived DB credentials. After the 2019 Capital One breach pattern, enforcing non-password DB auth in IaC review is a standard compensating control.
