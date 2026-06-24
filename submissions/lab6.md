# Lab 6 — Submission

## Task 1: Checkov on Terraform + Pulumi

### Terraform scan

* Total checks: 94
* Passed: 35
* Failed: 59

| Severity           | Count |
| ------------------ | ----: |
| Critical           |     0 |
| High               |     0 |
| Medium             |     0 |
| Low                |     0 |

### Top 5 rule IDs (by frequency)

| Rule ID     | Count | What it checks                                                                                    |
| ----------- | ----: | ------------------------------------------------------------------------------------------------- |
| CKV_AWS_355 |     4 | Ensure no IAM policy document allows `"*"` as a resource for restrictable actions.                |
| CKV_AWS_289 |     4 | Ensure IAM policies do not allow permissions management or resource exposure without constraints. |
| CKV_AWS_382 |     3 | Ensure no security groups allow unrestricted egress (`0.0.0.0/0`) to all ports and protocols.     |
| CKV_AWS_290 |     3 | Ensure IAM policies do not allow write access without constraints.                                |
| CKV_AWS_288 |     3 | Ensure IAM policies do not allow data exfiltration.                                               |

### Pulumi scan

| Severity           | Count |
| ------------------ | ----: |
| Unspecified (null) |     2 |

### Module-leverage analysis (Lecture 6 slide 17)

The most impactful module-level improvement would be enforcing restrictive IAM policy templates in the shared Terraform modules. The three most frequent findings (CKV_AWS_355, CKV_AWS_289, and CKV_AWS_290) are all related to overly permissive IAM policies, together accounting for 11 findings. If the module generated IAM policies with least-privilege defaults and prevented wildcard resources or unconstrained permissions, multiple findings would be eliminated automatically across all deployed resources.

## Task 2: KICS on Ansible

### Severity breakdown

| Severity | Count |
| -------- | ----: |
| HIGH     |     3 |
| MEDIUM   |     0 |
| LOW      |     1 |
| INFO     |     0 |

### Top 5 KICS queries (by frequency)

| Query                                    | Severity | Files |
| ---------------------------------------- | -------- | ----: |
| Passwords And Secrets - Generic Password | HIGH     |     6 |
| Passwords And Secrets - Password in URL  | HIGH     |     2 |
| Passwords And Secrets - Generic Secret   | HIGH     |     1 |
| Unpinned Package Version                 | LOW      |     1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

**One thing Checkov did better for the Terraform sample**

Checkov provided deep cloud-specific security analysis for AWS resources and identified a large number of infrastructure misconfigurations, especially around IAM policies, networking, encryption, and access control. Its policy library is highly focused on cloud compliance and best practices, making it particularly effective for Terraform-based infrastructure.

**One thing KICS did better for the Ansible sample**

KICS was very effective at detecting hardcoded credentials and secrets embedded directly in Ansible playbooks and inventory files. It identified multiple passwords, secret keys, and credentials in URLs, which are common security issues in configuration-management code and may not be covered as thoroughly by Terraform-focused scanners.

**(Optional) An example of a finding only ONE of them caught for the same resource type**

KICS detected several secret-management issues such as "Generic Password", "Generic Secret", and "Password in URL" within Ansible files. These findings are specific to configuration content and credential exposure, whereas Checkov focused primarily on cloud-resource misconfigurations such as overly permissive IAM policies and insecure AWS resource settings.
