# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan (passed/failed per framework)

| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 35 | 57 |
| secrets | 0 | 2 |

### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_355 | 4 | Ensure no IAM policy document allows `"*"` as a resource for restrictable actions. |
| CKV_AWS_289 | 4 | Ensure IAM policies do not allow permissions management or resource exposure without constraints. |
| CKV_AWS_382 | 3 | Ensure no security groups allow unrestricted egress (`0.0.0.0/0`) to all ports and protocols. |
| CKV_AWS_290 | 3 | Ensure IAM policies do not allow write access without constraints. |
| CKV_AWS_288 | 3 | Ensure IAM policies do not allow data exfiltration. |

### Module-leverage analysis (Lecture 6 slide 17)

The most impactful module-level improvement would be enforcing restrictive IAM policy templates in the shared Terraform modules. The three most frequent findings (CKV_AWS_355, CKV_AWS_289, and CKV_AWS_290) are all related to overly permissive IAM policies, together accounting for 11 findings. If the shared IAM policy module enforced least-privilege defaults by removing wildcard resources and unconstrained permissions, these findings would be eliminated automatically across every resource using the module.

---

## Task 2: KICS on Ansible + Pulumi

### Ansible — severity breakdown

| Severity | Count |
|----------|------:|
| HIGH | 3 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

### Pulumi — severity breakdown

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |

### Top 5 KICS queries — Ansible (by frequency)

| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

**One thing Checkov did better for the Terraform sample**

Checkov provided deep cloud-specific analysis for Terraform resources and identified numerous AWS infrastructure misconfigurations, especially around IAM policies, networking, encryption, and access control. Its rule set is optimized for cloud infrastructure security and infrastructure-as-code best practices.

**One thing KICS did better for the Ansible sample**

KICS was particularly effective at detecting hardcoded credentials and secrets embedded in Ansible playbooks. It also identified configuration issues such as passwords in URLs and unpinned package versions, demonstrating its strong support for configuration-management files beyond Terraform.

**(Optional) An example of a finding only ONE of them caught for the same resource type**

KICS detected several secret-management issues such as "Generic Password", "Generic Secret", and "Password in URL" in the Ansible playbooks. In contrast, Checkov focused on cloud-specific infrastructure misconfigurations, such as overly permissive IAM policies and unrestricted security group rules in the Terraform configuration.
