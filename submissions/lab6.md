# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Scan summary
- Checkov version: **3.3.2**
- Total checks evaluated: **127**
- Passed: **49**
- Failed: **78**
- Resources scanned: **16**

### Severity breakdown
| Severity | Count |
|----------|------:|
| HIGH     |    78 |
| Medium   |     0 |
| Low      |     0 |

> *Note: Checkov Community Edition without a Bridgecrew API key buckets all failed checks under HIGH. Granular severity metadata requires the commercial platform key.*

### Top 5 failed checks by frequency
| Rule ID | Count | Description |
|---------|------:|-------------|
| CKV_AWS_289 | 4 | IAM policies must not allow broad permissions-management actions without constraints |
| CKV_AWS_355 | 4 | IAM policy documents must not use wildcard `*` as the resource for actions that can be scoped |
| CKV_AWS_23  | 3 | Every security group and security group rule must include a description |
| CKV_AWS_288 | 3 | IAM policies must not allow data-exfiltration actions without constraints |
| CKV_AWS_290 | 3 | IAM policies must not allow unrestricted write-level access |

### Module-leverage analysis (Lecture 6 slide 17)

The seven hits for `CKV_AWS_289` and `CKV_AWS_355` all stem from a single `aws_iam_policy` declaration in `iam.tf` that declares `Effect = "Allow"` with `Action = "*"` and `Resource = "*"`. Replacing that one wildcard policy with a least-privilege module — one that accepts an explicit list of actions and scoped resource ARNs as input variables — would wipe out the entire top-two rule cluster in one commit. This is exactly the module-level leverage idea from the lecture: the misconfiguration is authored once, but every resource that consumes the module inherits the flaw, so repairing the module repairs every downstream instance automatically.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible scan
| Severity | Count |
|----------|------:|
| HIGH     |     3 |
| LOW      |     1 |
| **Total**|   **4** |

### Top KICS queries on Ansible
| Query | Severity | Files affected |
|-------|----------|---------------:|
| Passwords And Secrets — Generic Password | HIGH | 6 |
| Passwords And Secrets — Password in URL | HIGH | 2 |
| Passwords And Secrets — Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Pulumi scan (KICS native YAML support)
| Severity | Count |
|----------|------:|
| CRITICAL |     1 |
| HIGH     |     2 |
| MEDIUM   |     1 |
| INFO     |     2 |
| **Total**|   **6** |

### Top KICS queries on Pulumi
| Query | Severity | Files affected |
|-------|----------|---------------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets — Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

**Where Checkov outperforms:**
On Terraform HCL, Checkov’s graph engine traces dependencies across resources — for example, it can follow an IAM policy to the role it attaches to, then to the EC2 instance that assumes the role, and flag the whole chain. It also emits fine-grained CKV_AWS_* rule IDs that map directly onto CIS AWS Foundations Benchmark controls, which makes compliance reporting straightforward. Against the same infrastructure expressed in Pulumi YAML, KICS returned only six findings, whereas Checkov produced 78 on the HCL version because its parser is purpose-built for Terraform.

**Where KICS outperforms:**
KICS treats Ansible YAML as a first-class format: it understands `vars`, `tasks`, `handlers`, and module names (`apt`, `mysql_db`, `copy`) natively in its Rego queries. That let it catch a hardcoded MySQL connection string inside a `mysql_db` task — something Checkov does not surface in Ansible context. KICS also scanned the Pulumi YAML files directly without requiring a rendered state or cloud credentials, which is a practical win in CI pipelines where `pulumi preview` may not be available.

**Finding caught by only one tool:**
KICS flagged `Passwords And Secrets — Password in URL` inside `configure.yml` (a MySQL connection string containing `admin:SuperSecret`). Checkov has no equivalent rule for Ansible playbook content. Conversely, Checkov flagged `CKV_AWS_23` (missing security group description) on Terraform resources — a HCL-specific hygiene check with no KICS counterpart in Ansible.

---

## Bonus: Custom Checkov Policy

### Policy file (`labs/lab6/policies/my-custom-policy.yaml`)

```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: "RDS instance must have IAM database authentication enabled"
  category: "ENCRYPTION"
  severity: HIGH

definition:
  and:
    - cond_type: "attribute"
      resource_types:
        - "aws_db_instance"
      attribute: "iam_database_authentication_enabled"
      operator: "equals"
      value: true
```

### Verification — rule fires on 2 resources

| Check ID | Resource | File | Lines | Severity |
|----------|----------|------|-------|----------|
| CKV2_CUSTOM_1 | `aws_db_instance.unencrypted_db` | database.tf | 5–37 | HIGH |
| CKV2_CUSTOM_1 | `aws_db_instance.weak_db` | database.tf | 40–69 | HIGH |

### Why this rule matters

Static database credentials are long-lived secrets that survive in configuration files, environment variables, and backup snapshots. If an attacker compromises an EC2 instance or gains access to a repository, those passwords provide a direct path to the data tier. Enabling IAM database authentication replaces static passwords with short-lived auth tokens that are generated on demand and tied to the IAM principal of the requesting instance. This removes the persistent credential from the attack surface and aligns with the principle of least privilege, because access can be revoked centrally through IAM policy rather than by rotating a shared password. The control is also referenced in CIS AWS Foundations Benchmark v1.5 (control 2.3.1) and NIST SP 800-53 IA-5 (Authenticator Management).
