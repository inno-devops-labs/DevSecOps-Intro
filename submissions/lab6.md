# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

- Total checks: 127
- Passed: 49
- Failed: 78

| Severity | Count |
| -------- | ----: |
| Critical |     0 |
| High     |     0 |
| Medium   |     0 |
| Low      |     0 |
| null     |    78 |

### Top 5 rule IDs (by frequency)

| Rule ID     | Count | What it checks                                                                                  |
| ----------- | ----: | ----------------------------------------------------------------------------------------------- |
| CKV_AWS_289 |     4 | Ensure IAM policies do not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 |     4 | Ensure no IAM policies documents allow "\*" as a statement's resource for restrictable actions  |
| CKV_AWS_23  |     3 | Ensure every security group and rule has a description                                          |
| CKV_AWS_288 |     3 | Ensure IAM policies do not allow data exfiltration                                              |
| CKV_AWS_290 |     3 | Ensure IAM policies do not allow write access without constraints                               |

### Module-leverage analysis (Lecture 6 slide 17)

Looking at your top-5 Terraform rules, which ONE fix would eliminate the most findings if applied
at the module level? (2-3 sentences. e.g., "If the S3 module had `block_public_acls = true` as default,
the 8 findings of CKV_AWS_56 would all go away.")

- Looking at the top-5 Terraform rules, 4 out of 5 are IAM-related (CKV_AWS_289, 355, 288, 290), all triggered by overly permissive IAM policies with wildcard actions (`"Action": "*"`) or wildcard resources (`"Resource": "*"`). If the platform team created a hardened IAM module that enforces least-privilege by default — for example, a module that requires explicit action lists and resource ARNs, and rejects wildcard permissions — all 14 IAM-related findings would be eliminated in a single fix. This is the highest-leverage move: fix the IAM module once, and every team consuming it automatically gets compliant policies.

## Task 2: KICS on Ansible + Pulumi

### Ansible Severity Breakdown

| Severity | Count |
| -------- | ----: |
| HIGH     |     9 |
| MEDIUM   |     0 |
| LOW      |     1 |
| INFO     |     0 |

### Top KICS Queries for Ansible (by frequency)

| Query                                    | Severity | Files Affected |
| ---------------------------------------- | -------- | -------------: |
| Passwords And Secrets - Generic Password | HIGH     |              6 |
| Passwords And Secrets - Password in URL  | HIGH     |              2 |
| Passwords And Secrets - Generic Secret   | HIGH     |              1 |
| Unpinned Package Version                 | LOW      |              1 |

### Pulumi Severity Breakdown (via KICS)

| Severity | Count |
| -------- | ----: |
| CRITICAL |     1 |
| HIGH     |     2 |
| MEDIUM   |     1 |
| INFO     |     2 |

**Key Pulumi Findings:**

- **CRITICAL:** RDS DB Instance Publicly Accessible (`Pulumi-vulnerable.yaml:104`)
- **HIGH:** DynamoDB Table Not Encrypted, Hardcoded Database Password

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

- **One thing Checkov did better for the Terraform sample:**
  Checkov leverages a graph engine to evaluate relationships between Terraform resources, allowing it to catch cross-resource misconfigurations like an S3 bucket lacking an attached Public Access Block (`CKV2_AWS_6`) or unattached Security Groups (`CKV2_AWS_5`). It also provides exact line-level remediation guidance for HCL, making fixes highly actionable for developers.

- **One thing KICS did better for the Ansible sample:**
  KICS natively understands Ansible's imperative YAML structure and inventory formats, allowing it to easily detect hardcoded secrets like `ansible_password` in `inventory.ini` and embedded credentials in git repo URLs. Checkov's Ansible support is comparatively basic and often misses these context-specific secret patterns outside of standard task files.

- **An example of a finding only ONE of them caught for the same resource type:**
  KICS caught multiple hardcoded passwords in the Ansible `inventory.ini` file, which Checkov completely missed because it lacks deep parsing for Ansible inventory formats. Conversely, Checkov caught graph-based Terraform issues like unattached Security Groups, which KICS did not flag for the equivalent resources.

## Bonus: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)

```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure RDS instances have deletion protection enabled"
  category: "GENERAL_SECURITY"
  severity: "HIGH"
definition:
  and:
    - cond_type: "filter"
      attribute: "resource_type"
      value: ["aws_db_instance"]
      operator: "within"
    - cond_type: "attribute"
      resource_types: ["aws_db_instance"]
      attribute: "deletion_protection"
      operator: "equals"
      value: true
```

### Rule fires

Output of `jq '.[0].results.failed_checks[] | select(.check_id == "CKV2_CUSTOM_1") | {resource, file_path}'`:

```json
{
  "resource": "aws_db_instance.unencrypted_db",
  "file_path": "/database.tf"
}
{
  "resource": "aws_db_instance.weak_db",
  "file_path": "/database.tf"
}
```

### Why this rule matters

Deletion protection prevents the accidental or malicious termination of critical database instances. In real-world scenarios, rogue insiders or compromised CI/CD pipelines with overly permissive IAM roles could issue a `terraform destroy` or `aws rds delete-db-instance` command, leading to catastrophic data loss and extended downtime. This aligns with compliance requirements such as the CIS AWS Foundations Benchmark and NIST 800-53 CP-9 (Information System Backup), which mandate safeguards against the unauthorized destruction of critical data stores.
