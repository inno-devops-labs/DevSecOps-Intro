# Lab 6 — IaC Security: Checkov, KICS, and a Policy You Write

## Task 1

I scanned the Terraform sample with Checkov. The terraform reported 49 passed and 78 failed checks, "secrets" reported 0 passed and 2 failed.

The five most frequent failed rules were:

- CKV_AWS_289 — 4 findings. Checks whether IAM policies allow permissions management or resource exposure without constraints.
- CKV_AWS_355 — 4 findings. Checks for `Resource = "*"` where IAM actions can be restricted to specific resources.
- CKV_AWS_23 — 3 findings. Checks whether security groups and their rules have descriptions.
- CKV_AWS_288 — 3 findings. Checks whether IAM policies allow data exfiltration.
- CKV_AWS_290 — 3 findings. Checks whether IAM policies allow write access without constraints.

I would first replace the wildcard policy in "labs/lab6/vulnerable-iac/terraform/iam.tf", resource "aws_iam_policy.admin_policy", with permissions limited to the workload’s required actions and resources. This resource accounts for nine failed checks. On a temporary copy, replacing Action = "*" and Resource = "*" with "s3:GetObject" on one bucket’s object ARN cleared all nine. Several rules flag the same broad grant, so one policy change resolves multiple findings rather than requiring nine separate edits.

"severity" is null for every finding in this Checkov report. In a real backlog, I would prioritize by exposure, likely impact and blast radius, then group findings that share a cause. Vendor severity could help with initial sorting, but it cannot replace reviewing the resource and its context.


## Task 2

The Ansible scan reported 10 individual findings: 9 High and 1 Low. In the JSON, these are grouped into 4 distinct queries: 3 High and 1 Low. The Pulumi scan reported 6 individual findings—1 Critical, 2 High, 1 Medium and 2 Info—and each came from a different query, so its query breakdown is the same.

Only four queries fired in Ansible, so there is no fifth to list. Ordered by the number of ".files" entries shown:

- **Passwords And Secrets - Generic Password:** 6 matches across 3 distinct files.
- **Passwords And Secrets - Password in URL:** 2 matches in 1 file.
- **Passwords And Secrets - Generic Secret:** 1 match in 1 file.
- **Unpinned Package Version:** 1 match in 1 file.

KICS found a publicly accessible RDS instance in the Pulumi YAML file. That Pulumi resource does not appear in the Checkov results because Checkov scanned Terraform and does not parse Pulumi as a framework. Conversely, Checkov found overly broad IAM policies in Terraform, while the KICS commands scanned only Ansible and Pulumi. This difference reflects the formats covered by these runs, it's not show that KICS cannot scan Terraform.

I would run Checkov for Terraform and KICS for Ansible and Pulumi in this repository’s pipeline. KICS assigns severities, while this Checkov report gives pass/fail results with null severity, so their verdicts need different triage. I would review exposed databases and hardcoded credentials promptly, checking each finding against the affected resource. I would also record which formats each job covers so a clean result for one format is not mistaken for complete IaC coverage.

## Bonus

```
metadata:
  id: CKV_CUSTOM_1
  name: Ensure RDS identifiers follow the internal corp- naming standard
  category: CONVENTION
  severity: LOW

definition:
  cond_type: attribute
  resource_types:
    - aws_db_instance
  attribute: identifier
  operator: starting_with
  value: corp-
```
"CKV_CUSTOM_1" requires every RDS instance identifier to begin with "corp-".

The scan JSON shows the rule firing on both RDS resources:

    [
      {
        "check_id": "CKV_CUSTOM_1",
        "resource": "aws_db_instance.unencrypted_db",
        "file_path": "/database.tf"
      },
      {
        "check_id": "CKV_CUSTOM_1",
        "resource": "aws_db_instance.weak_db",
        "file_path": "/database.tf"
      }
    ]

Changing their "identifier" values in "database.tf" from "mydb-unencrypted" and "mydb-weak" to "corp-unencrypted" and "corp-weak" makes the rule pass. I confirmed this on a temporary copy: Checkov reported 2 passed and 0 failed for "CKV_CUSTOM_1". The original vulnerable Terraform files were not changed.

This rule represents a proposed internal database naming standard for the lab, intended to make RDS resources identifiable in the team’s inventory. The "corp-" prefix is specific to that standard, so it would not make sense as a universal Checkov rule.
This rule implements DB-NAME-01, a proposed internal RDS naming standard for this lab, intended to make database instances identifiable 