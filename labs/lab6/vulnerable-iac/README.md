# Vulnerable Infrastructure-as-Code for Lab 6

⚠️ **WARNING: This directory contains intentionally vulnerable code for educational purposes only!**

## Overview

This directory contains deliberately insecure Terraform, Pulumi, and Ansible code designed for Lab 6 - Infrastructure-as-Code Security. Students will use security scanning tools to identify and understand these vulnerabilities.

## ⚠️ DO NOT USE IN PRODUCTION!

**These files contain serious security vulnerabilities and should NEVER be used in real environments.**

---

## 📂 Directory Structure

```
vulnerable-iac/
├── terraform/
│   ├── main.tf              # Public S3 buckets, hardcoded credentials
│   ├── security_groups.tf   # Overly permissive firewall rules
│   ├── database.tf          # Unencrypted databases, weak configurations
│   ├── iam.tf               # Wildcard IAM permissions
│   └── variables.tf         # Insecure default values
├── pulumi/
│   ├── __main__.py          # Python-based infrastructure with 21 security issues
│   ├── Pulumi.yaml          # Config with default secret values
│   ├── Pulumi-vulnerable.yaml  # YAML-based Pulumi manifest (for KICS scanning)
│   └── requirements.txt     # Python dependencies
└── ansible/
    ├── deploy.yml           # Hardcoded secrets, poor practices
    ├── configure.yml        # Weak SSH config, security misconfigurations
    └── inventory.ini        # Credentials in plaintext
```

---

## 🔴 Terraform Vulnerabilities (30 issues)

### Authentication & Credentials
1. Hardcoded AWS access key in provider configuration
2. Hardcoded AWS secret key in provider configuration
9. Hardcoded database password in plain text
30. Hardcoded API key in variables with default value

### Storage Security
2. S3 bucket with public-read ACL
3. S3 bucket without encryption configuration
4. S3 bucket public access block disabled
16. DynamoDB table without encryption

### Network Security
5. Security group allowing all traffic from 0.0.0.0/0
6. SSH (port 22) accessible from anywhere
6. RDP (port 3389) accessible from anywhere
7. MySQL (port 3306) exposed to internet
7. PostgreSQL (port 5432) exposed to internet

### Database Security
8. RDS instance without storage encryption
10. RDS instance publicly accessible
11. RDS backup retention set to 0 (no backups)
12. RDS deletion protection disabled
14. RDS multi-AZ disabled (no high availability)
15. RDS auto minor version upgrade disabled

### IAM & Permissions
18. IAM policy with wildcard (*) actions and resources
19. IAM role with full S3 access on all resources
20. IAM user with inline policy granting excessive permissions
21. IAM access keys created for service account
22. IAM credentials exposed in outputs without sensitive flag
23. IAM policy allowing privilege escalation paths

### Configuration Management
24. No region validation for resource deployment
25. Weak default password in variables
26. Public access enabled by default
27. Encryption disabled by default
28. SSH allowed from anywhere by default
29. Backup retention days set to 0 by default

---

## 🔴 Pulumi Vulnerabilities (21+ issues)

> **Note:** Pulumi code is provided in both Python (`__main__.py`) and YAML (`Pulumi-vulnerable.yaml`) formats. The YAML format is used for KICS scanning, which has first-class Pulumi YAML support.

### Authentication & Credentials  
1. Hardcoded AWS access key in provider
2. Hardcoded AWS secret key in provider  
3. Hardcoded database password in code
4. Hardcoded API key in code
21. Default config values with secrets in Pulumi.yaml

### Storage Security
3. S3 bucket with public-read ACL  
4. S3 bucket without encryption configuration
17. DynamoDB table without server-side encryption  
18. DynamoDB table without point-in-time recovery
19. EBS volume without encryption

### Network Security  
5. Security group allowing all traffic from 0.0.0.0/0
6. SSH and RDP accessible from anywhere

### Database Security
7. RDS instance without storage encryption  
8. RDS instance publicly accessible
9. RDS backup retention set to 0 (no backups)  
10. RDS deletion protection disabled

### IAM & Permissions
11. IAM policy with wildcard (*) actions and resources  
12. IAM role with full S3 access on all resources
16. Lambda function with overly permissive IAM role

### Compute Security  
13. EC2 instance without root volume encryption
14. Secrets exposed in EC2 user data

### Secrets Management
15. Secrets exposed in Pulumi outputs (not marked as secret)

### Logging & Monitoring  
20. CloudWatch log group without retention policy
20. CloudWatch log group without KMS encryption

---

## 🔴 Ansible Vulnerabilities (26 issues)

### Secrets Management
1. Hardcoded database password in playbook vars
2. Hardcoded API key in playbook vars
3. Database connection string with credentials
20. SSL private key in plaintext
38. Global variables with secrets in inventory
41. Production using same credentials as development

### Command Execution
4. Using shell module instead of proper apt module
5. MySQL command with password visible in logs
10. Downloading and executing script without verification
17. Shell command with potential injection vulnerability
32. Using raw module to flush firewall rules

### File Permissions & Access
6. Configuration file with 0777 permissions (world-writable)
7. SSH private key with 0644 permissions (should be 0600)
16. Downloaded file with 0777 permissions

### Authentication & Access Control
21. SELinux disabled
22. Passwordless sudo for all commands
23. SSH PermitRootLogin enabled
23. SSH PasswordAuthentication enabled
23. SSH PermitEmptyPasswords enabled
34. Authorized key added for root user

### Logging & Monitoring
5. Sensitive command without no_log flag
13. Password hashing without no_log
14. Debug output exposing secrets
18. Password visible in task name
26. Passwords logged in plaintext files

### Network Security
9. Firewall (ufw) disabled
25. Application listening on 0.0.0.0 (all interfaces)

### Credential Management
11. Git credentials hardcoded in repository URL
35. Credentials in inventory file
36. Using root user with password authentication
37. SSH private key path in plaintext inventory

### Configuration Security
15. Using 'latest' instead of pinned versions
24. Installing unnecessary development tools on production
28. Insecure temp file handling with predictable names
29. No timeout for long-running tasks
31. Fetching sensitive files without encryption
33. No checksum validation for templates
39. Insecure SSH connection settings (StrictHostKeyChecking=no)
40. No connection timeout configured

### Error Handling
12. Ignoring errors for critical database migrations
30. No proper error handling in assertions

---

## 🛠️ Tools Used in This Lab

| Format | Tool | Why |
|--------|------|-----|
| **Terraform** | **Checkov 3.x** | ~2,500 built-in policies; native HCL support (Task 1) |
| **Pulumi** | **KICS (Checkmarx)** | First-class Pulumi YAML support; Checkov has no Pulumi framework (Task 2) |
| **Ansible** | **KICS (Checkmarx)** | Comprehensive Rego-based Ansible queries (Task 2) |
| **Policy-as-Code** | **Custom Checkov policy (YAML)** | Catch organization-specific rules the catalog doesn't ship (Bonus) |

See `labs/lab6.md` for the exact commands.

---

## 📋 Expected Student Outcomes

Students should:
1. Surface the security vulnerabilities across the Terraform, Pulumi, and Ansible samples
   - Note: Pulumi code includes both Python and YAML formats; KICS scans the YAML
2. Triage findings by rule frequency (Checkov) and severity (KICS) to find the highest-leverage fixes
3. Compare how Checkov (HCL) and KICS (Rego) surface different findings on the same resource types
4. Evaluate KICS's first-class Pulumi support and query catalog
5. Write a custom Checkov policy to catch an organization-specific rule the catalog doesn't ship
6. Reason about tool selection (Checkov vs KICS) for a CI/CD pipeline

---

## 🔧 How to Use (Students)

Scan these samples in place — no copying needed. Follow `labs/lab6.md` step by step:

- **Task 1** — `checkov -d labs/lab6/vulnerable-iac/terraform ...`
- **Task 2** — `kics scan -p .../ansible/` and `kics scan -p .../pulumi/`
- **Bonus** — re-run Checkov with `--external-checks-dir labs/lab6/policies`

> Don't fix these files — analyze them. The findings are the deliverable.

---

## 📚 Learning Resources

- [OWASP Infrastructure as Code Security](https://owasp.org/www-project-devsecops/)
- [Terraform Security Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)
- [Pulumi Security Best Practices](https://www.pulumi.com/docs/guides/crossguard/)
- [Ansible Security Best Practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CIS Distribution Independent Linux Benchmark](https://www.cisecurity.org/benchmark/distribution_independent_linux)

---

## 🔒 Security Notice

**These files are for educational purposes only. They contain intentional security vulnerabilities that would compromise real systems. Never deploy this code to any environment connected to the internet or containing real data.**

---

## ✅ Validation

To verify students have completed the lab successfully, check that they:
- [ ] Ran Checkov on the Terraform sample and reported real findings (top-5 rules + passed/failed)
- [ ] Ran KICS on both the Ansible and Pulumi samples and reported real severities
- [ ] Compared Checkov (HCL) vs KICS (Rego) with concrete examples
- [ ] Identified a module-level fix that clears multiple Terraform findings at once
- [ ] (Bonus) Wrote a custom Checkov policy that demonstrably fires on the sample
- [ ] Explained Checkov-vs-KICS tool selection rationale

---

*Lab created for F25-DevSecOps-Intro course*
