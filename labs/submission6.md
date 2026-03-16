# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement
# Terraform & Pulumi Security Scanning

## Tool Comparison

| Tool | Findings |
|--|--|
| tfsec | 53 |
| Checkov | 78 |
| Terrascan | 22 |

From here:

| Metric              | tfsec | Checkov | Terrascan |
|--|--|--|--|
| **Total findings**  | 53    | 78      | 22        |
| **CRITICAL**        | 9     | -       | 0         |
| **HIGH**            | 25    | -       | 14        |
| **MEDIUM**          | 11    | -       | 8         |
| **LOW**             | 8     | -       | 0         |

### Differences

Among the tested tools, **Checkov** reported the highest number of issues This likely means that it has the largest rule database and performs more extensive checks

**tfsec** detected slightly fewer findings, but the results were very clear and specifically focused on Terraform security best practices Detected biggest amount of CRITICAL vulnerabilities (9)

**Terrascan** reported the smallest number of issues This tool seems more focused on policy validation and compliance checks rather than detecting every possible misconfiguration


## Tool Strengths

### tfsec
- Fast and lightweight scanner
- Easy to read reports
- Low number of false positives

### Checkov
- Large rule database
- Supports multiple IaC frameworks
- Detects issues related to IAM, encryption and configuration security

### Terrascan
- Good for enforcing security policies
- Useful for compliance checks



# Pulumi Security Analysis (KICS)

| Severity | Findings |
|--|--|
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| Total | 6 |

### Observed Issues

Most important vulns identified:
- RDS DB instance is publicly accessible
- Network configuration issues
- DynamoDB table are not encrypted
- Hardcoded secrets


## KICS Pulumi Support

KICS can analyze the Pulumi configuration and detect security problems automatically (supported)

Advantages of KICS:
- Open source scanner
- Natively supports Pulumi YAML scans
- Multiple output formats (JSON, HTML, stdout, etc)
- Uses a large open-source rule catalog
- Generates reports in JSON and HTML


# Terraform vs Pulumi Security Issues

Pulumi results were smaller since only **KICS** was used and the configuration was smaller (only 6 results)

Based on the results, **Terraform currently has much stronger support from security scanning tools**
Multiple mature scanners exist and they detect most of the issues in the configuration

For **Pulumi**, the main open-source scanning option is **KICS**, and its rule catalog for Pulumi is still relatively small, which leads to fewer detected findings



# Critical Security Findings

## Hardcoded secrets in Ansible Playbook
```
vars:
  db_password: "SuperSecret123!"
  api_key: "sk_live_1234567890abcdef"
  db_connection: "postgresql://admin:password123@dbexamplecom:5432/myapp"
```
- Issue: leaked creds
- Risk: anyone can use them to gain full unauthorized access
- Fix: remove all secrets from git history and never commit them again

## Publicly accessible S3 Buckets
```
resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucketexampleid

  block_public_acls   = false
  block_public_policy = false
}
```
- Issue: Storage buckets are publicly accessible
- Risk: Potential senditive data exposure
- Fix: set `block_public_acls` and `block_public_policy` to `true`

## Hardcoded AWS keys
```
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```
- Issue: leaked creds
- Risk: anyone can use them to gain full unauthorized access
- Fix: remove all secrets from git history and never commit them again

## Security Groups
- Issue: Security groups allow access from whole inet (`0000/0`)
- Risk: Attackers can access all services from the internet
- Fix: Define publicly accessible scope

## Plaintext DB
- Issue: DB encryption disabled
- Risk: Full data theft on storage compromise
- Fix: Encrypt sensitive data in DB 

## Tool Selection Guide

**tfsec**

Use tfsec if:

- You need a quick Terraform security scan  
- Security checks should run in pre-commit hooks  
- Developers need fast feedback during development  

**Checkov**

Use Checkov if:

- You are scanning infrastructure across multiple cloud providers  
- Broader rule coverage is required  
- Security and compliance policies need to be validated  

**Terrascan**

Use Terrascan if:

- Policy-as-code enforcement is important  
- Infrastructure must be validated against compliance frameworks (PCI, HIPAA, etc)

**KICS**

Use KICS if:

- You need to scan Pulumi or Ansible configurations  
- One tool should support several IaC frameworks  
- Detailed queries and rule definitions are required

## CI/CD Integration Strategy

A simple DevSecOps pipeline could include several security stages

**1 Pre-commit stage**

- Tool: tfsec  
- Why: run quick Terraform checks before code is committed  

**2 Pull request / CI stage**

- Tools: Checkov and KICS  
- Why: perform deeper infrastructure scanning before merging code  

**3 Extended security scan**

- Tools: Terrascan and Checkov  
- Why: detect compliance problems and additional configuration issues  

**4 Release check**

- Tools: all scanners  
- Why: final validation before deploying infrastructure to production  


## Justification

Using several tools together provides better coverage because each scanner focuses on different types of issues

- Some tools detect Terraform misconfigurations more effectively
- Others focus on compliance rules or multi-framework support
- Running scans at different stages of the pipeline helps catch problems earlier

This layered approach improves security by reducing the chance that important vulnerabilities remain undetected


## Lessons Learned

- During this lab I understood that different IaC security tools have different strengths and limitations

- One important observation is that **no single tool detects all security issues** Each scanner focuses on specific types of misconfigurations, so using multiple tools together provides better coverage

- Another insight is related to **tool effectiveness** Tools like tfsec and Checkov detected many Terraform issues quickly and produced clear reports Checkov generally provided the most comprehensive results because of its larger rule set

- I also noticed that **false positives can occur**, especially when scanners interpret configuration context differently This means findings should always be reviewed manually before making changes

Overall, combining multiple scanners and integrating them into the development workflow improves the chances of detecting security problems early
