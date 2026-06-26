# Lab 6 — Submission

## Environment and tool versions

```text
Docker: Docker version 29.5.2, build 79eb04c7d8
jq: jq-1.8.1-dirty
Checkov mode: local
Checkov: 3.3.2
KICS: Keeping Infrastructure as Code Secure v2.1.20
```

The files under `labs/lab6/vulnerable-iac/` were scanned but intentionally not modified.

## Task 1: Checkov on Terraform

### Terraform scan

- Total evaluated checks: **127**
- Passed: **49**
- Failed: **78**
- Skipped: **0**
- Parsing errors: **0**

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |
| Unspecified | 78 |
| **Total failed** | **78** |

`Unspecified` means the local open-source Checkov result did not attach a severity value to that built-in policy.

### Top 5 rule IDs by frequency

| Rule ID | Count | What it checks | Severity |
|---------|------:|----------------|----------|
| `CKV_AWS_289` | 4 | Ensure IAM policies does not allow permissions management / resource exposure without constraints | Unspecified |
| `CKV_AWS_355` | 4 | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions | Unspecified |
| `CKV_AWS_23` | 3 | Ensure every security group and rule has a description | Unspecified |
| `CKV_AWS_288` | 3 | Ensure IAM policies does not allow data exfiltration | Unspecified |
| `CKV_AWS_290` | 3 | Ensure IAM policies does not allow write access without constraints | Unspecified |

### Module-leverage analysis

I would fix **CKV_AWS_289 — Ensure IAM policies does not allow permissions management / resource exposure without constraints** at the shared module level first. It accounts for **4** failed resource checks in this scan, so enforcing the secure default once in the reusable Terraform module would remove every repeated instance and prevent the same misconfiguration from being reintroduced by callers.

## Task 2: KICS on Ansible and Pulumi

### Ansible severity breakdown

| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total findings** | **10** |

### Pulumi severity breakdown

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total findings** | **6** |

### Top 5 KICS queries by finding count

| Query | Severity | Findings | Platform |
|-------|----------|---------:|----------|
| Passwords And Secrets - Generic Password | HIGH | 6 | Ansible |
| Passwords And Secrets - Password in URL | HIGH | 2 | Ansible |
| RDS DB Instance Publicly Accessible | CRITICAL | 1 | Pulumi |
| DynamoDB Table Not Encrypted | HIGH | 1 | Pulumi |
| Passwords And Secrets - Generic Password | HIGH | 1 | Pulumi |

### Checkov versus KICS

**What Checkov did better for Terraform:** Checkov produced Terraform-native resource identifiers, CKV rule IDs, source ranges, and graph-aware relationships that make repeated failures easy to trace back to one shared module or resource definition.

**What KICS did better for Ansible:** KICS recognized configuration-management tasks and evaluated them using Ansible-specific queries instead of treating the playbook as generic YAML. Findings therefore retain task and module context.

**Pulumi trade-off:** KICS was run directly against the supplied Pulumi directory, and the table reflects only what the current parser and query catalog actually recognized. IaC coverage must be verified per source language and representation rather than assumed from a product-level support label.

## Bonus: Custom Checkov Policy

### Policy file

```yaml
---
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure all taggable AWS resources declare the project ownership tag"
  category: "CONVENTION"
  severity: "MEDIUM"
  guideline: "Internal tagging standard: every cloud resource must identify its owning project"
scope:
  provider: "aws"
definition:
  cond_type: "attribute"
  resource_types: "taggable"
  attribute: "tags.project"
  operator: "exists"
```

### Rule fires

The custom scan produced **12** failed check(s) with a `CKV2_CUSTOM_*` identifier. One representative result is:

```json
{
  "check_id": "CKV2_CUSTOM_1",
  "check_name": "Ensure all taggable AWS resources declare the project ownership tag",
  "severity": "MEDIUM",
  "resource": "aws_db_instance.unencrypted_db",
  "file_path": "/database.tf",
  "file_line_range": [
    5,
    37
  ]
}
```

### Why this rule matters

A mandatory `tags.project` value creates an ownership link between deployed cloud resources and the responsible system. During an incident, missing ownership metadata delays containment and remediation because responders cannot quickly identify the service owner; it also weakens inventory, cost-allocation, and decommissioning workflows. Enforcing the tag before deployment turns that requirement into a repeatable policy-as-code control.

## Final verification checklist

- [x] Checkov scanned the deliberately vulnerable Terraform directory.
- [x] Checkov counts and top rules were generated from actual JSON.
- [x] KICS scanned both Ansible and Pulumi directories.
- [x] KICS tables were generated from actual JSON.
- [x] Module-level triage identifies one concrete high-leverage rule.
- [x] `CKV2_CUSTOM_1` was accepted and fired.
- [x] Regenerable scanner output remains outside the commit.
