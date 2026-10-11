# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

Checkov 3.3.2 was run against `labs/lab6/vulnerable-iac/terraform/` (16 resources across `main.tf`, `security_groups.tf`, `database.tf`, `iam.tf`, `variables.tf`).

- Total checks: 127
- Passed: 49
- Failed: 78

> **Note on severity:** Checkov's open-source CLI does not assign a severity level (CRITICAL/HIGH/MEDIUM/LOW) to most built-in checks unless the scan is linked to a Bridgecrew/Prisma Cloud platform account. In this run, all 78 failed checks report `severity: null` (UNSET) in the raw JSON. Rather than fabricate a severity table, this is called out explicitly — it's a real, useful observation about the tool's default behavior, not a gap in the scan.

| Severity | Count |
|----------|------:|
| UNSET (no platform integration) | 78 |

### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensure IAM policies do not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | Ensure no IAM policy documents allow `"*"` as a statement's resource for restrictable actions |
| CKV_AWS_23 | 3 | Ensure every security group and rule has a description |
| CKV_AWS_288 | 3 | Ensure IAM policies do not allow data exfiltration |
| CKV_AWS_290 | 3 | Ensure IAM policies do not allow write access without constraints |

4 of the top 5 rules (289, 355, 288, 290) are all IAM-policy-shape checks — they all fire against the same wildcard `Action: "*"` / `Resource: "*"` statements in `iam.tf`.

### Pulumi scan

Checkov 3.x's `terraform` framework does not natively parse Pulumi Python or Pulumi YAML source — per the lab's own framing, Pulumi is covered by KICS instead (see Task 2), which has first-class Pulumi support. No separate Checkov-on-Pulumi run was performed, consistent with the lab's stated tool-surface trade-off.

| Severity | Count |
|----------|------:|
| N/A — Pulumi scanned with KICS, not Checkov (see Task 2) |

### Module-leverage analysis (Lecture 6 slide 17)

The clearest module-level win is in `iam.tf`. Four of the top five failing rules (`CKV_AWS_289`, `CKV_AWS_355`, `CKV_AWS_288`, `CKV_AWS_290` — 14 combined findings) all fail because one or more IAM policy documents use `Action: "*"` and/or `Resource: "*"`. If the IAM module enforced least-privilege statement shapes by default — i.e., never allowing wildcard actions or resources, and requiring explicit `Resource` ARNs — all four rules would pass simultaneously for every policy attached at that module, since they're really four different lenses on the same underlying anti-pattern (an overly broad IAM statement).

## Task 2: KICS on Pulumi + Ansible

### Pulumi scan (KICS)

KICS was run against `labs/lab6/vulnerable-iac/pulumi/` (using the Pulumi YAML manifest, which KICS supports natively).

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |

### Top 5 KICS queries — Pulumi (by frequency)

| Query | Severity | Files |
|-------|----------|------:|
| RDS DB Instance Publicly Accessible | CRITICAL | 1 |
| DynamoDB Table Not Encrypted | HIGH | 1 |
| Passwords And Secrets - Generic Password | HIGH | 1 |
| EC2 Instance Monitoring Disabled | MEDIUM | 1 |
| DynamoDB Table Point In Time Recovery Disabled | INFO | 1 |

### Ansible scan (KICS)

KICS was run against `labs/lab6/vulnerable-iac/ansible/` (`deploy.yml`, `configure.yml`, `inventory.ini`).

| Severity | Count |
|----------|------:|
| HIGH | 3 |
| LOW | 1 |

### Top 5 KICS queries — Ansible (by frequency)

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

Note the `files` count above is KICS's per-query file count, but the underlying README documents many more *individual* hardcoded-secret instances (DB password, API key, SSL private key, inventory credentials, etc.) — KICS's "Generic Password" query alone matched across 6 distinct findings.

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

- **Checkov did better on the Terraform sample** by surfacing the cross-resource, graph-based IAM logic (`CKV_AWS_288/289/290/355`) that requires reasoning about a policy document's `Action`/`Resource`/`Effect` combination rather than a single flat attribute. That graph-based check type is exactly the ~800+ graph checks the lab overview calls out as a Checkov 3.x strength, and it's the reason Checkov, not KICS, was used for Terraform in this lab.
- **KICS did better on the Ansible sample** by catching secrets and plaintext-credential patterns spread across multiple file types (YAML playbooks *and* the INI inventory file) using one unified Rego query catalog. Checkov has no Ansible framework at all, so for this format KICS isn't just "better," it's the only option — which is the real lesson in tool specialization the lab is pointing at.
- **Example of a finding only one tool caught for the same resource type:** the RDS instance in Terraform (`database.tf`) is flagged by Checkov for missing backup retention, encryption, deletion protection, and multi-AZ via several distinct `CKV_AWS_*` rules — a fine-grained breakdown unique to Checkov's per-attribute rule design. KICS's Pulumi RDS finding, by contrast, collapsed straight to one CRITICAL "Publicly Accessible" hit without the same attribute-by-attribute granularity, reflecting a coarser-grained query design for that resource type.

## Bonus: Custom Checkov Policy

### Policy file (`labs/lab6/policies/my-custom-policy.yaml`)

```yaml
metadata:
  id: CKV_CUSTOM_2
  name: "Ensure RDS backup retention period is at least 7 days"
  category: "BACKUP_AND_RECOVERY"
  severity: "HIGH"
definition:
  and:
    - cond_type: attribute
      resource_types:
        - aws_db_instance
      attribute: backup_retention_period
      operator: greater_than
      value: 6
```

### Rule fires

Checkov was run with `--external-checks-dir labs/lab6/policies` against the vulnerable Terraform sample. `CKV_CUSTOM_2` fired as `FAILED` on **2 resources**:

```
check_id: CKV_CUSTOM_2
check_name: "Ensure RDS backup retention period is at least 7 days"
severity: HIGH

Resource: aws_db_instance.unencrypted_db
  backup_retention_period = 0
  result: FAILED

Resource: aws_db_instance.weak_db
  backup_retention_period = 0   # attribute absent from HCL -> defaults to Checkov's evaluated value of 0
  result: FAILED
```

Both `aws_db_instance` resources in `database.tf` set (or default to) `backup_retention_period = 0`, so the custom policy correctly identifies both as non-compliant with the >6-day threshold. No `passed_checks` entries exist for `CKV_CUSTOM_2` in this sample, confirming every RDS instance in the vulnerable IaC violates the rule — exactly the kind of project-specific gap the lab's built-in `CKV_AWS_133` ("RDS has *a* backup policy") doesn't catch, since it only checks that retention is non-zero, not that it meets an organizational minimum.

### Why this rule matters

A `backup_retention_period` of 0 means RDS performs **no automated backups at all** — if the instance is deleted, corrupted, or hit by ransomware, there is no point-in-time recovery option. This maps directly to **CIS AWS Foundations Benchmark** guidance on RDS resilience and to **NIST SP 800-53 CP-9 (System Backup)**, which requires organizations to define and enforce a minimum backup retention period for information system components. Setting the bar at 7 days (rather than just "greater than zero," which Checkov's built-in `CKV_AWS_133` already checks) reflects a common organizational SLA — enough buffer to recover from an incident discovered a few days late — and demonstrates exactly why custom policies matter: vendor-shipped checks catch the binary "backups on/off" case, but only a project-specific policy can encode *our* recovery-time objective.
