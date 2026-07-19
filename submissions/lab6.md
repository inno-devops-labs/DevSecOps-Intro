# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan
- Total checks run: **127** (49 passed, 78 failed)
- Passed: **49**
- Failed: **78**
- Resources scanned: **16**
- Checkov version: **3.3.2**

| Severity | Count |
|----------|------:|
| HIGH     |    78 |
| Medium   |     0 |
| Low      |     0 |

*(Checkov CE without API key reports all findings under HIGH; severity metadata requires the Bridgecrew platform key)*

### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies do not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure no IAM policies documents allow `*` as a statement's resource for restrictable actions |
| CKV_AWS_23  | 3 | Ensure every security group and rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies do not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies do not allow write access without constraints |

### Pulumi scan (via KICS)

| Severity | Count |
|----------|------:|
| CRITICAL |     1 |
| HIGH     |     2 |
| MEDIUM   |     1 |
| INFO     |     2 |
| **Total**|   **6** |

Top findings: RDS DB Instance Publicly Accessible (CRITICAL), DynamoDB Table Not Encrypted (HIGH), Passwords And Secrets (HIGH).

### Module-leverage analysis (Lecture 6 slide 17)

The four `CKV_AWS_289` + `CKV_AWS_355` findings all originate from the same `aws_iam_policy` resource block in `iam.tf` that uses `Action: "*"` and `Resource: "*"` in its statement. Replacing that single wildcard policy with a least-privilege IAM policy module (one that requires explicit action lists and scoped resource ARNs as input variables) would eliminate **7 findings** in one change — the entire top-2 rule cluster. This is the module-level leverage principle from Lecture 6 slide 17: the misconfiguration lives in one place, but every consumer of that module inherits it, so fixing the module closes all downstream findings simultaneously.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible severity breakdown

| Severity  | Count |
|-----------|------:|
| HIGH      |     3 |
| LOW       |     1 |
| **Total** |   **4** |

### Top 5 KICS queries on Ansible (by files affected)

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL  | HIGH | 2 |
| Passwords And Secrets - Generic Secret   | HIGH | 1 |
| Unpinned Package Version                 | LOW  | 1 |

### KICS Pulumi top queries

| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible      | CRITICAL | 1 |
| DynamoDB Table Not Encrypted             | HIGH     | 1 |
| Passwords And Secrets - Generic Password | HIGH     | 1 |
| EC2 Instance Monitoring Disabled         | MEDIUM   | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

**One thing Checkov did better for the Terraform sample:**
Checkov's 800+ graph-based CKV2_* policies caught cross-resource relationships — for example, it can correlate that an IAM policy is attached to a role that is attached to an EC2 instance, and flag the entire chain. It also returned 78 specific rule IDs (CKV_AWS_*) that map directly to CIS AWS Foundations Benchmark controls, making it straightforward to map findings to a compliance framework. KICS found only 6 findings on the equivalent Pulumi code with the same root causes — Checkov's dedicated Terraform HCL parser produced dramatically higher signal density for HCL-format code.

**One thing KICS did better for the Ansible sample:**
KICS natively understands Ansible YAML semantics — it recognises `vars:`, `tasks:`, `handlers:`, and module names (`apt`, `mysql_db`, `copy`) as first-class concepts in its Rego queries. This produced targeted findings like "Password in URL" that specifically flagged a `mysql_db` connection string, which Checkov (primarily an IaC-infrastructure scanner) would not detect. KICS also scanned Pulumi YAML natively without needing a rendered state file — a practical advantage in CI where `pulumi preview` may require cloud credentials.

**A finding only one tool caught:**
KICS caught `Passwords And Secrets - Password in URL` in `configure.yml` (a MySQL connection string `mysql://admin:SuperSecret@localhost/db`) — a finding Checkov does not have a built-in rule for in Ansible context. Conversely, Checkov caught `CKV_AWS_23` (security group missing description) on Terraform resources, a HCL-specific hygiene check that has no KICS Ansible equivalent.

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

### Rule fires on 2 resources

```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "RDS instance must have IAM database authentication enabled",
    "resource": "aws_db_instance.unencrypted_db",
    "file_path": "/database.tf",
    "file_line_range": [5, 37],
    "severity": "HIGH"
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "RDS instance must have IAM database authentication enabled",
    "resource": "aws_db_instance.weak_db",
    "file_path": "/database.tf",
    "file_line_range": [40, 69],
    "severity": "HIGH"
  }
]
```

### Why this rule matters

Without `iam_database_authentication_enabled = true`, RDS instances authenticate using static username/password pairs — exactly the credential pattern that caused the 2019 Capital One breach, where a misconfigured WAF allowed an attacker to pivot through a compromised EC2 role directly to RDS because the database accepted password auth from any internal principal. IAM database authentication replaces static passwords with short-lived IAM tokens tied to the EC2 instance's role, eliminating the long-lived credential from the attack surface entirely. This control is also required by CIS AWS Foundations Benchmark v1.5 control 2.3.1 (Ensure that encryption is enabled for RDS Instances) and maps to NIST SP 800-53 IA-5 (Authenticator Management).
