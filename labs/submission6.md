# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## 1. Terraform Tool Comparison

Three different scanners were used to analyze the Terraform infrastructure code.

### Scan Results

| Tool      | Findings |
| --------- | -------- |
| tfsec     | 53       |
| Checkov   | 78       |
| Terrascan | 22       |


### Observations

`Checkov` detected the largest number of issues. This is expected because it contains a very large policy catalog and evaluates many best-practice rules in addition to strict security vulnerabilities.

`tfsec` produced slightly fewer results but focuses on high-quality Terraform-specific checks, which usually leads to fewer false positives.

`Terrascan` detected the smallest number of issues because it focuses primarily on policy and compliance violations, rather than all possible security misconfigurations.

### Types of Detected Terraform Issues

Examples of vulnerabilities identified by the scanners include:
- Publicly accessible databases
- Unencrypted storage
- Open security groups
- Hardcoded AWS credentials
- Overly permissive IAM policies
- Public S3 buckets
- Missing logging and monitoring

These issues represent critical infrastructure risks that could expose sensitive resources.

## 2. Pulumi Security Analysis

Pulumi infrastructure code was analyzed using KICS.

### Scan Results

| Severity | Findings |
| -------- | -------- |
| Critical | 1        |
| High     | 2        |
| Medium   | 1        |
| Info     | 2        |
| Total    | 6        |

### Key Detected Issues

The following major security problems were identified:

- **Publicly accessible RDS database (CRITICAL)**

    The RDS instance was configured with publiclyAccessible: true, allowing direct access from the internet.

- **Unencrypted DynamoDB table (HIGH)**

    Server-side encryption was not enabled.

- **Hardcoded secrets (HIGH)**

    Credentials were stored directly inside the Pulumi configuration.

- **EC2 monitoring disabled (MEDIUM)**
    
    Detailed monitoring was not enabled.

- **DynamoDB point-in-time recovery disabled (INFO)**

- **EC2 instance not EBS optimized (INFO)**

### Evaluation of KICS Pulumi Support

KICS demonstrated strong Pulumi support by detecting:
- Encryption issues
- Access control problems
- Secret exposure
- Observability misconfigurations

The Pulumi-specific queries correctly identified AWS resource misconfigurations directly from the YAML infrastructure definitions.

## 3. Terraform vs Pulumi

Terraform and Pulumi both define cloud infrastructure but use different approaches.

| Feature              | Terraform                 | Pulumi                       |
| -------------------- | ------------------------- | ---------------------------- |
| Language             | HCL                       | YAML / programming languages |
| Infrastructure style | Declarative               | Programmatic                 |
| Scanner ecosystem    | Very mature               | Still developing             |
| Tools used           | tfsec, Checkov, Terrascan | KICS                         |

### Key Differences

**Terraform**:
- More mature ecosystem
- Large number of dedicated scanners
- Strong community support
- Extensive policy libraries

**Pulumi**:
- Supports programming languages
- Smaller scanning ecosystem
- Requires multi-platform tools like KICS

Despite different approaches, **both technologies** can suffer from the same misconfigurations such as:
- public infrastructure exposure
- lack of encryption
- poor IAM configuration
- missing monitoring

## 4. KICS Pulumi Support

KICS provides a comprehensive catalog of security queries covering:
- AWS
- Azure
- GCP
- Kubernetes
- Generic secret detection


## 5. Critical Findings

In this lab the tool successfully detected issues across multiple categories:

| Category          | Example Issue                |
| ----------------- | ---------------------------- |
| Encryption        | DynamoDB table not encrypted |
| Access Control    | Public RDS instance          |
| Secret Management | Hardcoded credentials        |
| Observability     | Monitoring disabled          |
| Best Practices    | Backup and recovery disabled |

The queries are effective at identifying both security vulnerabilities and operational risks.

## 6. Tool Strengths

### tfsec
- scanning Terraform only
- fast CI/CD scans
- minimizing false positives

### Checkov
- scanning multiple IaC frameworks
- enforcing security policies
- detecting many configuration issues

### Terrascan
- compliance checks are required
- OPA policy enforcement is needed

### KICS
- scanning Pulumi and Ansible
- multi-platform IaC scanning
- secret detection

## 7. Ansible Security Issues

KICS was used to analyze Ansible playbooks.

### Scan Results

| Severity | Findings |
| -------- | -------- |
| High     | 9        |
| Medium   | 0        |
| Low      | 1        |
| Total    | 10       |

### Main Security Problems

The most common issue detected was hardcoded secrets.

Example findings:
- Hardcoded passwords
- Credentials inside inventory files
- Secrets embedded in playbooks
- Passwords included in URLs

These issues violate secure configuration management practices.

## 8. Best Practice Violations

### 1. Hardcoded Secrets

Sensitive information such as passwords and API keys were stored directly in playbooks and inventory files.

Security Risk:
- Secrets exposed in version control
- Unauthorized access to infrastructure
- Increased risk of credential leaks

### 2. Passwords in URLs

Credentials embedded in URLs may appear in logs or monitoring tools.

Example:

```
http://user:password@host
```

Security Risk:
- Password exposure through logs
- Potential credential leakage

### 3. Unpinned Package Versions

The following configuration was detected:

```
state: latest
```

Security Risk:
- Unexpected upgrades
- Supply chain risks
- Deployment instability

## 10. Remediation Steps

### Fix Hardcoded Secrets

Use Ansible Vault or environment variables.

Example:

```
ansible-vault encrypt secrets.yml
```

or

```
password: "{{ vault_database_password }}"
```

### Secure RDS Configuration

Example fix for Pulumi:

```
publiclyAccessible: false
```

### Enable Encryption

Example DynamoDB configuration:

```
serverSideEncryption:
  enabled: true
```

### Restrict Security Groups

Instead of allowing all traffic:

```
cidr_blocks = ["0.0.0.0/0"]
```

Use restricted networks:

```
cidr_blocks = ["10.0.0.0/16"]
```

## 11. Tool Comparison Matrix

| Criterion         | tfsec                    | Checkov             | Terrascan         | KICS                    |
| ----------------- | ------------------------ | ------------------- | ----------------- | ----------------------- |
| Total Findings    | 53                       | 78                  | 22                | 16                      |
| Scan Speed        | Fast                     | Medium              | Medium            | Medium                  |
| False Positives   | Low                      | Medium              | Low               | Medium                  |
| Report Quality    | ⭐⭐⭐                      | ⭐⭐⭐⭐                | ⭐⭐⭐               | ⭐⭐⭐⭐                    |
| Ease of Use       | ⭐⭐⭐⭐                     | ⭐⭐⭐                 | ⭐⭐⭐               | ⭐⭐⭐                     |
| Documentation     | ⭐⭐⭐⭐                     | ⭐⭐⭐⭐                | ⭐⭐⭐               | ⭐⭐⭐                     |
| Platform Support  | Terraform                | Multi-IaC           | Multi-IaC         | Multi-IaC               |
| Output Formats    | JSON, text               | JSON, CLI           | JSON, CLI         | JSON, HTML              |
| CI/CD Integration | Easy                     | Easy                | Medium            | Easy                    |
| Unique Strength   | Terraform specialization | Huge policy library | Compliance checks | Multi-platform scanning |

## 12. Category Analysis

| Security Category           | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
| --------------------------- | ----- | ------- | --------- | ------------- | -------------- | --------- |
| Encryption Issues           | ✓     | ✓       | ✓         | ✓             | –              | Checkov   |
| Network Security            | ✓     | ✓       | ✓         | ✓             | –              | tfsec     |
| Secrets Management          | –     | ✓       | ✓         | ✓             | ✓              | KICS      |
| IAM / Permissions           | ✓     | ✓       | ✓         | –             | –              | Checkov   |
| Access Control              | ✓     | ✓       | ✓         | ✓             | –              | tfsec     |
| Compliance / Best Practices | ✓     | ✓       | ✓         | ✓             | ✓              | Terrascan |

## 13. Top 5 Critical Findings

### 1. Public RDS Database

**Risk**

Attackers can access the database directly from the internet.

**Fix**

```
publiclyAccessible: false
```

### 2. Hardcoded Credentials

**Risk**

Secrets exposed in source control.

**Fix**

Use secret management tools like:
- Ansible Vault
- AWS Secrets Manager
- Environment variables

### 3. Open Security Groups

Example vulnerability:

```
0.0.0.0/0
```

**Risk**

Allows unrestricted network access.

**Fix**

Restrict allowed IP ranges.

### 4. Unencrypted DynamoDB Table

**Risk**

Sensitive data stored without encryption.

**Fix**

```
serverSideEncryption:
  enabled: true
```

### 5. Public S3 Buckets

**Risk**

Sensitive data exposure.

**Fix**

Enable public access block.

## 11. Tool Selection Guide

### tfsec

Best used when:
- scanning Terraform only
- fast CI/CD scans
- minimizing false positives

### Checkov

Best used when:
- scanning multiple IaC frameworks
- enforcing security policies
- detecting many configuration issues

### Terrascan

Best used when:
- compliance checks are required
- OPA policy enforcement is needed

### KICS

Best used when:
- scanning Pulumi and Ansible
- multi-platform IaC scanning
- secret detection

## 12. Lessons Learned

Several insights were gained during this lab.

### Tool effectiveness varies

Different scanners detect different issues due to varying policy sets.

### No single tool is sufficient

Combining multiple scanners improves security coverage.

### Secret detection is critical

Many IaC vulnerabilities come from exposed credentials.

### Infrastructure misconfiguration is common

Public access and missing encryption were frequent issues.

### Security scanning should be automated

Integrating IaC scanners into CI/CD pipelines is essential for preventing insecure deployments.

## 13. CI/CD Integration Strategy

A practical DevSecOps pipeline could use multiple scanners.

### Example pipeline

Stage 1 — Fast checks

```
tfsec
```

Stage 2 — Deep policy scan

```
checkov
```

Stage 3 — Compliance verification

```
terrascan
```

Stage 4 — Multi-IaC scanning

```
kics
```

This layered approach improves vulnerability detection coverage.
