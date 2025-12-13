## Task 1

> Compare effectiveness of `tfsec` vs. `Checkov` vs. `Terrascan`

Using the given configurations,  `tfsec` has identified 53 findings, `Checkov` identified 78 findings, `Terrascan` identified 22 findings.

> Document findings from KICS on Pulumi code

| Name                                           | Description                                                                                                                                                                                                                        | Severity | CWE | Risk Score |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | --- | ---------- |
| EC2 Not EBS Optimized                          | It's considered a best practice for an EC2 instance to use an EBS optimized instance. This provides the best performance for your EBS volumes by minimizing contention between Amazon EBS I/O and other traffic from your instance | INFO     | 459 | 0.0        |
| DynamoDB Table Point In Time Recovery Disabled | It's considered a best practice to have point in time recovery enabled for DynamoDB Table                                                                                                                                          | INFO     | 459 | 0.0        |
| EC2 Instance Monitoring Disabled               | EC2 Instance should have detailed monitoring enabled. With detailed monitoring enabled data is available in 1-minute periods                                                                                                       | MEDIUM   | 778 | 5.1        |
| Passwords And Secrets - Generic Password       | Query to find passwords and secrets in infrastructure code                                                                                                                                                                         | HIGH     | 798 | 7.8        |
| DynamoDB Table Not Encrypted                   | AWS DynamoDB Tables should have serverSideEncryption enabled                                                                                                                                                                       | HIGH     | 311 | 7.1        |
| RDS DB Instance Publicly Accessible            | RDS must not be defined with public interface, which means the attribute 'PubliclyAccessible' must be set to false                                                                                                                 | CRITICAL | 284 | 8.7        |

> Compare security issues between declarative HCL and programmatic YAML approaches

Security issues of the Terraform (HCL) environment mostly describe network mismanagement, with multiple databases and management ports (SSH, RDP) exposed publicly.

On the other hand, security issues on the **Pulumi (YAML)** environment are more focused around credentials mishandling and not enabling secure policies like encryption.

> Document 5 significant security issues

| Issue                                          | Description                                                                                              | Severity | File                 | Line |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------- | -------- | -------------------- | ---- |
| RDS Instance Publicly Accessible               | RDS database is configured with a public IP address (`publicly_accessible = true`)                       | **HIGH** | `database.tf`        | 5    |
| Unrestricted Administrative Access (SSH & RDP) | The security group allows ingress on port 22 (SSH) and 3389 (RDP) from `0.0.0.0/0` (the entire internet) | **HIGH** | `security_groups.tf` | 31   |
| S3 Buckets with public ACLs                    | The configuration flags S3 buckets that have both a public ACL and lack a "Public Access Block"          | **HIGH** | `main.tf`            | 13   |
| Unencrypted RDS Storage                        | The underlying storage for the RDS instance is not encrypted, failing common compliance requirements     | **HIGH** | `database.tf`        | 5    |
| Unrestricted Database Ports (Postgres/MySQL)   | Security groups allow traffic from `0.0.0.0/0` to ports 5432 (PostgreSQL) and 3306 (MySQL)               | **HIGH** | `security_groups.tf` | 65   |


> What does each tool excel at detecting?

| Tool          | Primary Focus              | Excels At                                                                                                                                                        | Best For                                                                                            |
| ------------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **tfsec**     | **Terraform** Specific     | **Speed & Simplicity**  <br>Extremely fast execution; excellent VS Code integration; developer-friendly output.                                                  | **Developers** wanting a lightweight, instant-feedback linter for Terraform.                        |
| **checkov**   | **Broad** IaC & Compliance | **Graph-based Scanning**  <br>Understands resource relationships (e.g., "This EC2 is connected to this Security Group"); massive compliance library (CIS, SOC2). | **DevSecOps** teams needing to audit complex architectures across many frameworks (TF, K8s, Bicep). |
| **kics**      | **Widest** Format Support  | **Platform Coverage**  <br>Supports the largest number of file types (Ansible, Docker, Helm, CDK, etc.) out of the box.                                          | **Enterprise** environments with diverse technology stacks beyond just Terraform.                   |
| **terrascan** | **Cloud Native** Standards | **OPA/Rego Standardization**  <br>Native integration with Open Policy Agent; focuses on policy-as-code consistency across runtime and build time.                | **Platform Engineers** building strict Policy-as-Code pipelines aligned with OPA standards.         |

## Task 2

| Security Issue           | Best Practice Violation                                                             | KICS Query Type                             | Remediation Steps                                                                 |
| ------------------------ | ----------------------------------------------------------------------------------- | ------------------------------------------- | --------------------------------------------------------------------------------- |
| Hardcoded Secrets        | Credentials are stored in plain text within configuration files                     | `Passwords And Secrets - Generic Password`​ | Store the secrets in a secret manager, make it part of the infrastructure         |
| Passwords in URLs        | Database connection strings and Git repository URLs contain embedded credentials    | `Passwords And Secrets - Password in URL`​  | Construct URLs dynamically, obtaining secrets dynamically from the secret manager |
| Unpinned Package Version | The package manager is set to `state: latest`, making deployments non-deterministic | `Unpinned Package Version` ​                | Specify the exact package versions                                                |
