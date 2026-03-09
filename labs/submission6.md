# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

**Branch:** `feature/lab6`  
**Target:** `labs/lab6/vulnerable-iac/` (Terraform, Pulumi, Ansible)

---

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1 Environment Setup

Created analysis directory and pulled all required Docker images:

```powershell
New-Item -ItemType Directory -Force -Path labs/lab6/analysis
```

All tool images pulled successfully:
- `aquasec/tfsec:latest`
- `bridgecrew/checkov:latest`
- `tenable/terrascan:latest`
- `checkmarx/kics:latest`

---

### 1.2 Terraform Scanning Results

#### tfsec — 53 Findings

```powershell
docker run --rm -v "${PWD}/labs/lab6/vulnerable-iac/terraform:/src" `
  aquasec/tfsec:latest /src --format json | Out-File -Encoding utf8 labs/lab6/analysis/tfsec-results.json
```

**Severity distribution (tfsec):**

| Severity | Count |
|----------|------:|
| CRITICAL | 9 |
| HIGH | 25 |
| MEDIUM | 11 |
| LOW | 8 |
| **Total** | **53** |

**Sample findings (first 10):**

| Rule ID | Severity | Description |
|---------|----------|-------------|
| AVD-AWS-0023 | HIGH | Table encryption is not enabled |
| AVD-AWS-0024 | MEDIUM | Point-in-time recovery is not enabled |
| AVD-AWS-0025 | LOW | Table encryption does not use a customer-managed KMS key |
| AVD-AWS-0124 | LOW | Security group rule does not have a description (×3) |
| AVD-AWS-0104 | CRITICAL | Security group rule allows egress to multiple public internet addresses (×3) |
| AVD-AWS-0107 | CRITICAL | Security group rule allows ingress from public internet |

---

#### Checkov — 78 Findings

```powershell
docker run --rm -v "${PWD}/labs/lab6/vulnerable-iac/terraform:/tf" `
  bridgecrew/checkov:latest -d /tf --framework terraform `
  -o json | Out-File -Encoding utf8 labs/lab6/analysis/checkov-terraform-results.json
```

Checkov reported **78 failed checks** — the highest count among all three Terraform tools. Its policy-as-code engine covers a broader set of checks including resource tagging, logging, backup policies, and compliance best practices that tfsec and Terrascan do not check by default.

> **Note:** The version of Checkov used (`bridgecrew/checkov:latest`) does not populate a `severity` field in its JSON output for Terraform checks — all 78 `failed_checks` entries have a blank `severity` value. Severity information must be inferred from the check descriptions and Bridgecrew documentation.

**Sample findings (first 15 unique checks):**

| Check ID | Description |
|----------|-------------|
| CKV_AWS_16 | Ensure all data stored in the RDS is securely encrypted at rest |
| CKV_AWS_17 | Ensure all data stored in RDS is not publicly accessible |
| CKV_AWS_18 | Ensure the S3 bucket has access logging enabled |
| CKV_AWS_20 | S3 Bucket has an ACL defined which allows public READ access |
| CKV_AWS_21 | Ensure all data stored in the S3 bucket have versioning enabled |
| CKV_AWS_23 | Ensure every security group and rule has a description |
| CKV_AWS_24 | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 |
| CKV_AWS_25 | Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 |
| CKV_AWS_28 | Ensure DynamoDB point in time recovery (backup) is enabled |
| CKV_AWS_40 | Ensure IAM policies are attached only to groups or roles |
| CKV_AWS_41 | Ensure no hard coded AWS access key and secret key exists in provider |
| CKV_AWS_53 | Ensure S3 bucket has block public ACLS enabled |
| CKV_AWS_62 | Ensure no IAM policies documents allow "*-*" administrative privileges |
| CKV_AWS_63 | Ensure no IAM policies documents allow "*" as a statement's actions |
| CKV_AWS_161 | Ensure RDS database has IAM authentication enabled |

**JSON evidence (excerpt from `checkov-terraform-results.json`):**

```json
{
  "summary": {
    "passed": 48,
    "failed": 78,
    "parsing_error": 0
  }
}
```

---

#### Terrascan — 22 Findings

```powershell
docker run --rm -v "${PWD}/labs/lab6/vulnerable-iac/terraform:/iac" `
  tenable/terrascan:latest scan -i terraform -d /iac `
  -o json | Out-File -Encoding utf8 labs/lab6/analysis/terrascan-results.json
```

Terrascan reported **22 violated policies** — the lowest count among Terraform tools. Terrascan focuses on compliance-mapped controls (PCI-DSS, HIPAA, CIS) and does not flag stylistic or best-practice issues, resulting in a tighter, lower-noise finding set.

**Severity distribution (Terrascan):**

| Severity | Count |
|----------|------:|
| HIGH | 14 |
| MEDIUM | 8 |
| LOW | 0 |
| **Total** | **22** |

**All Terrascan findings:**

| Rule Name | Severity | Description |
|-----------|----------|-------------|
| rdsPubliclyAccessible | HIGH | RDS Instance publicly_accessible flag is true |
| rdsHasStorageEncrypted | HIGH | RDS database instances must encrypt underlying storage (AES-256) |
| rdsAutoMinorVersionUpgradeEnabled | HIGH | RDS Instance Auto Minor Version Upgrade flag disabled |
| rdsBackupDisabled | HIGH | Ensure automated backups are enabled for AWS RDS instances (×2) |
| rdsLogExportDisabled | MEDIUM | Ensure CloudWatch logging is enabled for AWS DB instances (×2) |
| rdsIamAuthEnabled | MEDIUM | Ensure that your RDS database has IAM Authentication enabled (×2) |
| s3Versioning | HIGH | Enabling S3 versioning enables easy recovery from unintended user actions (×2) |
| s3PublicAclNoAccessBlock | HIGH | Ensure S3 buckets do not have both public ACL and public access block |
| allUsersReadAccess | HIGH | Misconfigured S3 buckets can leak private information to the entire internet |
| dynamoDbEncrypted | MEDIUM | Ensure DynamoDB is encrypted at rest |
| dynamoderecovery_enabled | MEDIUM | Ensure Point In Time Recovery is enabled for DynamoDB Tables |
| port22OpenToInternet | HIGH | Security Groups — Unrestricted Specific Ports (SSH, 22) |
| port3306AlbNetworkPortSecurity | HIGH | Security Groups — Unrestricted Specific Ports (MySQL, TCP 3306) |
| port3389OpenToInternet | HIGH | Security Groups — Unrestricted Specific Ports (RDP, TCP 3389) |
| port5432AlbNetworkPortSecurity | HIGH | Security Groups — Unrestricted Specific Ports (PostgreSQL, TCP 5432) |
| portWideOpenToPublic | HIGH | Ensure no security group allows traffic from 0.0.0.0/0 to ALL ports |
| iamUserInlinePolicy | MEDIUM | Ensure IAM policies are attached only to groups or roles |
| programmaticAccessCreation | MEDIUM | Ensure no exposed Amazon IAM access keys exist |

**JSON evidence (excerpt from `terrascan-results.json`):**

```json
{
  "results": {
    "scan_summary": {
      "file/folder": "/iac",
      "iac_type": "terraform",
      "policies_validated": 167,
      "violated_policies": 22,
      "low": 0,
      "medium": 8,
      "high": 14
    }
  }
}
```

---

#### Terraform Tool Comparison Summary

| Tool | Findings | Approach | Strength |
|------|------:|----------|---------|
| tfsec | 53 | Rule-based, Terraform-specific | Best coverage of AWS security misconfigs |
| Checkov | 78 | Policy-as-code, multi-framework | Broadest coverage including tagging, logging, backups |
| Terrascan | 22 | OPA-based, compliance-mapped | Lowest noise, best for compliance frameworks |

**Key observation:** The three tools overlap significantly on critical issues (open security groups, unencrypted databases, public S3 buckets, hardcoded credentials) but diverge on best-practice and compliance-oriented checks. Running tfsec and Checkov together provides the most comprehensive coverage for a CI/CD pipeline.

---

### 1.3 Pulumi Security Analysis (KICS)

```powershell
docker run -t --rm -v "${PWD}/labs/lab6/vulnerable-iac/pulumi:/src" `
  checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html
```

**KICS Pulumi severity distribution:**

| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |
| **Total** | **6** |

**All KICS Pulumi findings:**

| Finding | Severity | File |
|---------|----------|------|
| RDS DB Instance Publicly Accessible | CRITICAL | Pulumi-vulnerable.yaml |
| DynamoDB Table Not Encrypted | HIGH | Pulumi-vulnerable.yaml |
| Passwords And Secrets - Generic Password | HIGH | Pulumi-vulnerable.yaml |
| EC2 Instance Monitoring Disabled | MEDIUM | Pulumi-vulnerable.yaml |
| DynamoDB Table Point In Time Recovery Disabled | INFO | Pulumi-vulnerable.yaml |
| EC2 Not EBS Optimized | INFO | Pulumi-vulnerable.yaml |

> **Note on coverage:** KICS found 6 issues in `Pulumi-vulnerable.yaml`, while `__main__.py` contains 20 additional intentional vulnerabilities. To partially close this gap, Gitleaks was run on the Python file:
>
> ```powershell
> docker run --rm -v "${PWD}/labs/lab6/vulnerable-iac/pulumi:/src" `
>   zricethezav/gitleaks:latest detect --source /src --no-git `
>   --report-format json --report-path /src/gitleaks-report.json --exit-code 0
> ```
>
> Gitleaks found **1 additional secret** in `__main__.py`: a hardcoded Stripe API key at line 23. The AWS access key on line 16 was not flagged because Gitleaks allowlists that well-known AWS documentation example key. The remaining ~18 issues in `__main__.py` — open security groups, unencrypted EBS/RDS/DynamoDB, IAM wildcards, passwords in EC2 user-data, etc. — are infrastructure configuration issues expressed in Python API calls. No current open-source static tool can detect these in Pulumi Python code; Pulumi-aware analysis for the Python SDK does not yet exist in OSS tooling.

**JSON evidence (excerpt from `kics-pulumi-results.json`):**

```json
{
  "total_counter": 6,
  "severity_counters": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 1,
    "INFO": 2,
    "LOW": 0
  }
}
```

**KICS Pulumi query catalog evaluation:**

KICS auto-detected the `Pulumi-vulnerable.yaml` manifest and applied its dedicated Pulumi query catalog covering AWS, Azure, GCP, and Kubernetes resources. The scan correctly identified the most critical issue (publicly accessible RDS database), hardcoded credentials in the YAML config, and missing encryption on DynamoDB. The INFO-level findings (EBS optimization, PITR) represent configuration best practices rather than security vulnerabilities. KICS is currently the most capable open-source scanner for Pulumi YAML, as tools like tfsec and Checkov do not natively parse Pulumi manifests.

---

### 1.4 Terraform vs. Pulumi Security Comparison

Both Terraform (HCL) and Pulumi (YAML) exhibited the same classes of security issues, confirming these are architecture-level problems rather than framework-specific ones:

| Issue Category | Terraform (HCL) | Pulumi (YAML) |
|----------------|-----------------|---------------|
| Publicly accessible database | ✅ Present | ✅ Present |
| Unencrypted storage | ✅ Present | ✅ Present |
| Hardcoded credentials | ✅ Present | ✅ Present |
| Missing monitoring | ✅ Present | ✅ Present |
| Open security groups | ✅ Present | Not modeled |

One notable difference: Pulumi's programmatic nature (Python `__main__.py`) means secrets can be hidden inside variables or computed values, making them harder to detect statically than in declarative HCL. KICS only scanned the YAML manifest; the Python file would require a dedicated secrets scanner (e.g. Gitleaks, Semgrep) for full coverage.

---

### 1.5 Critical Findings — Top 5

**Finding 1: Security Group Open to the Internet (0.0.0.0/0) — CRITICAL**

- **Tool:** tfsec (AVD-AWS-0104, AVD-AWS-0107), Checkov, Terrascan
- **File:** `security_groups.tf`
- **Description:** Ingress and egress rules permit traffic from/to all public IP addresses (`0.0.0.0/0`) on all ports. This exposes every resource behind the security group to the entire internet.
- **Impact:** Any internet host can attempt to connect to EC2 instances, RDS databases, and internal services — enabling brute-force, exploitation, and data exfiltration.
- **Remediation:**
  ```hcl
  # BEFORE (vulnerable)
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # AFTER (secure)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Restrict to trusted CIDR only
    description = "Allow HTTPS from internal network"
  }
  ```

**Finding 2: RDS Database Publicly Accessible — CRITICAL**

- **Tool:** KICS (Pulumi), Checkov, tfsec
- **File:** `database.tf`, `Pulumi-vulnerable.yaml`
- **Description:** RDS instances have `publicly_accessible = true`, making the database endpoint resolvable and reachable from the public internet.
- **Impact:** Direct exposure of the database to internet-facing brute-force and exploitation attempts, bypassing all VPC network controls.
- **Remediation:**
  ```hcl
  # BEFORE (vulnerable)
  resource "aws_db_instance" "main" {
    publicly_accessible = true
  }

  # AFTER (secure)
  resource "aws_db_instance" "main" {
    publicly_accessible    = false
    db_subnet_group_name   = aws_db_subnet_group.private.name
    vpc_security_group_ids = [aws_security_group.db_sg.id]
  }
  ```

**Finding 3: Hardcoded Credentials in IaC — HIGH**

- **Tool:** tfsec, Checkov, KICS (Pulumi + Ansible)
- **Files:** `variables.tf`, `Pulumi-vulnerable.yaml`, `deploy.yml`, `configure.yml`, `inventory.ini`
- **Description:** AWS access keys, database passwords, and API secrets are hardcoded directly in IaC files and committed to version control.
- **Impact:** Any developer with repository access, or any attacker who gains read access to the repo (e.g., via a public fork, exposed backup, or CI artifact), can extract valid credentials and gain direct AWS or database access.
- **Remediation:**
  ```hcl
  # BEFORE (vulnerable)
  variable "db_password" {
    default = "SuperSecret123!"
  }

  # AFTER (secure) — use AWS Secrets Manager or environment variable
  variable "db_password" {
    description = "Database password — provided at runtime via TF_VAR_db_password"
    type        = string
    sensitive   = true
    # No default value — forces explicit supply at runtime
  }
  ```

**Finding 4: Unencrypted RDS and DynamoDB Storage — HIGH**

- **Tool:** tfsec (AVD-AWS-0023), Checkov, KICS (Pulumi)
- **Files:** `database.tf`, `main.tf`, `Pulumi-vulnerable.yaml`
- **Description:** RDS instances have `storage_encrypted = false` and DynamoDB tables have no server-side encryption configured.
- **Impact:** If database storage volumes are accessed offline (e.g., snapshot theft, misconfigured backup policy, insider threat), all data is readable in cleartext — violating GDPR, HIPAA, and PCI-DSS requirements.
- **Remediation:**
  ```hcl
  # BEFORE (vulnerable)
  resource "aws_db_instance" "main" {
    storage_encrypted = false
  }

  # AFTER (secure)
  resource "aws_db_instance" "main" {
    storage_encrypted = true
    kms_key_id        = aws_kms_key.rds_key.arn
  }

  resource "aws_dynamodb_table" "main" {
    server_side_encryption {
      enabled     = true
      kms_key_arn = aws_kms_key.dynamodb_key.arn
    }
  }
  ```

**Finding 5: Wildcard IAM Permissions — HIGH**

- **Tool:** tfsec, Checkov, Terrascan
- **File:** `iam.tf`
- **Description:** IAM policies grant `Action: "*"` on `Resource: "*"`, giving attached roles or users full administrative access to all AWS services and resources.
- **Impact:** A single compromised IAM credential or EC2 instance profile can be used to delete all resources, exfiltrate all data, create persistent backdoor accounts, or pivot to any other AWS service — complete account takeover.
- **Remediation:**
  ```hcl
  # BEFORE (vulnerable)
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }

  # AFTER (secure) — apply least-privilege principle
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject"
    ]
    resources = [
      "arn:aws:s3:::my-app-bucket/*"
    ]
  }
  ```

---

## Task 2 — Ansible Security Scanning with KICS

### 2.1 Scan Execution

```powershell
docker run -t --rm -v "${PWD}/labs/lab6/vulnerable-iac/ansible:/src" `
  checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html
```

**KICS Ansible severity distribution:**

| Severity | Count |
|----------|------:|
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| **Total** | **10** |

**All KICS Ansible findings (per file and line from `kics-ansible-results.json`):**

| Finding | Severity | File | Line |
|---------|----------|------|------|
| Passwords And Secrets - Generic Password | HIGH | configure.yml | 16 |
| Passwords And Secrets - Generic Password | HIGH | inventory.ini | 5 |
| Passwords And Secrets - Generic Password | HIGH | inventory.ini | 10 |
| Passwords And Secrets - Generic Password | HIGH | inventory.ini | 18 |
| Passwords And Secrets - Generic Password | HIGH | inventory.ini | 19 |
| Passwords And Secrets - Generic Password | HIGH | deploy.yml | 12 |
| Passwords And Secrets - Generic Secret | HIGH | inventory.ini | 20 |
| Passwords And Secrets - Password in URL | HIGH | deploy.yml | 16 |
| Passwords And Secrets - Password in URL | HIGH | deploy.yml | 72 |
| Unpinned Package Version | LOW | deploy.yml | 99 |

**JSON evidence (excerpt from `kics-ansible-results.json`):**

```json
{
  "total_counter": 10,
  "severity_counters": {
    "CRITICAL": 0,
    "HIGH": 9,
    "MEDIUM": 0,
    "LOW": 1,
    "INFO": 0
  }
}
```

---

### 2.2 Key Security Issues Identified

**Issue 1: Hardcoded Passwords in Inventory and Playbooks (HIGH × 9)**

The most prevalent finding across all three Ansible files. Passwords, API keys, and secrets are written in plaintext directly in `inventory.ini`, `deploy.yml`, and `configure.yml`. This is particularly dangerous for `inventory.ini` because inventory files are typically committed to version control and shared across the team.

**Security impact:** Any person with repository access — including contractors, former employees, or attackers who gain read access — can extract valid credentials. Ansible inventory files are frequently accidentally pushed to public repositories.

**Remediation:**
```yaml
# BEFORE (vulnerable) — inventory.ini
[webservers]
web1 ansible_host=192.168.1.10 ansible_user=admin ansible_password=SuperSecret123

# AFTER (secure) — use Ansible Vault
[webservers]
web1 ansible_host=192.168.1.10 ansible_user=admin

# Store secrets in a vault-encrypted vars file
# ansible-vault encrypt group_vars/all/vault.yml
# vault.yml:
# vault_ansible_password: !vault |
#   $ANSIBLE_VAULT;1.1;AES256
#   ...encrypted content...
```

**Issue 2: Password in Connection URL (HIGH × 2)**

Credentials are embedded directly inside connection strings (e.g., database URLs, API endpoints) in `deploy.yml`. URLs with embedded passwords appear in process lists, log files, and shell history — dramatically expanding the exposure surface beyond the file itself.

**Security impact:** Even if the playbook file is protected, credentials in URLs leak into application logs, system call traces (`/proc`), and Ansible task output — which may be stored in CI/CD logs and accessible to many more people.

**Remediation:**
```yaml
# BEFORE (vulnerable)
- name: Configure database connection
  shell: "mysql -u admin -pSuperSecret123 -h db.example.com mydb"

# AFTER (secure) — use no_log and separate credential variables
- name: Configure database connection
  community.mysql.mysql_db:
    login_host: "{{ db_host }}"
    login_user: "{{ db_user }}"
    login_password: "{{ vault_db_password }}"   # from Ansible Vault
    name: mydb
  no_log: true
```

**Issue 3: Unpinned Package Version (LOW)**

A package installation task in `deploy.yml` installs a package without specifying a version (e.g., `state: latest` or no version pin). While low severity, this is a significant supply chain risk.

**Security impact:** Unpinned packages introduce non-determinism into deployments. A malicious or buggy package update can be automatically installed the next time the playbook runs, potentially introducing vulnerabilities or breaking production systems.

**Remediation:**
```yaml
# BEFORE (vulnerable)
- name: Install application
  apt:
    name: nodejs
    state: latest

# AFTER (secure) — pin to a specific version
- name: Install application
  apt:
    name: nodejs=18.20.4-1nodesource1
    state: present
```

**Issue 4: Missing `no_log` on Sensitive Tasks (Manual Finding — not detected by KICS)**

Several tasks in `deploy.yml` and `configure.yml` handle sensitive data (passwords, API keys, connection strings) but do not include `no_log: true`. Ansible logs all task arguments to stdout and to any configured logging backends by default.

**Security impact:** Every CI/CD run that executes the playbook will print plaintext credentials to the build log. CI logs are typically retained for weeks or months and are accessible to anyone with pipeline read access — significantly broadening the credential exposure surface beyond the IaC file itself.

**Remediation:**
```yaml
# BEFORE (vulnerable) — credentials visible in Ansible output
- name: Create application user
  mysql_user:
    name: appuser
    password: "{{ db_password }}"
    host: "%"

# AFTER (secure) — suppress logging for sensitive tasks
- name: Create application user
  mysql_user:
    name: appuser
    password: "{{ vault_db_password }}"
    host: "%"
  no_log: true
```

> **KICS limitation:** KICS did not flag the absence of `no_log: true` because static analysis can detect the *presence* of a known bad pattern but not the *absence* of a required directive without deep task-semantic understanding. This type of check requires a custom rule or a dedicated Ansible linter (e.g., `ansible-lint` rule `no-log-password`).

---

### 2.3 KICS Ansible Query Evaluation

KICS auto-detected all three Ansible files (`deploy.yml`, `configure.yml`, `inventory.ini`) and applied its dedicated Ansible query catalog. The queries covered:

- **Secrets detection** — pattern-matched hardcoded passwords, API keys, tokens, and secrets in plaintext across all file types including INI inventory files
- **URL credential scanning** — detected passwords embedded in connection URLs, a check most general-purpose secret scanners miss
- **Package management** — flagged unpinned package versions as a supply chain risk

One notable gap: KICS did not flag the absence of `no_log: true` on sensitive tasks, which is a common Ansible security best practice. This is a known limitation — detecting the absence of a directive requires understanding task semantics, which is harder for static analysis than detecting the presence of a known bad pattern.

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Tool Effectiveness Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 16 (6 Pulumi + 10 Ansible) |
| **Scan Speed** | Fast | Medium | Medium | Medium |
| **False Positives** | Low | Medium | Low | Low |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Platform Support** | Terraform only | Terraform, CF, K8s, Docker | Terraform, K8s, Helm | Terraform, Pulumi, Ansible, K8s, Docker, CF |
| **Output Formats** | JSON, text, SARIF, JUnit | JSON, CLI, SARIF, JUnit, CycloneDX | JSON, YAML, XML, human | JSON, HTML, SARIF, JUnit, ASFF |
| **CI/CD Integration** | Easy | Easy | Medium | Easy |
| **Compliance Mapping** | CIS, NIST | CIS, NIST, SOC2, PCI | PCI-DSS, HIPAA, CIS | OWASP, CWE, CVE |
| **Unique Strengths** | Speed, low noise | Broadest checks, policy-as-code | Compliance frameworks | Multi-framework, Pulumi + Ansible |

---

### 3.2 Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|------:|--------:|----------:|:-------------:|:--------------:|-----------|
| **Encryption Issues** | 7 | 6 | 2 | 1 | N/A | tfsec |
| **Network Security** | 11 | 12 | 5 | 0 | N/A | Checkov |
| **Secrets Management** | 0 | 2 | 1 | 1 | 9 | KICS |
| **IAM / Permissions** | 10 | 22 | 1 | 0 | N/A | Checkov |
| **Access Control** | 12 | 10 | 3 | 1 | N/A | tfsec |
| **Compliance / Best Practices** | 13 | 26 | 10 | 3 | 0 | Checkov |
| **Supply Chain** | 0 | 0 | 0 | 0 | 1 | KICS |

**Key observations:**
- **KICS** is uniquely effective at secrets detection across all file types including Ansible inventory files and Pulumi YAML — 9 of 10 Ansible findings and 1 Pulumi finding are secrets, far exceeding all Terraform tools (tfsec: 0, Checkov: 2, Terrascan: 1)
- **Checkov** leads in IAM/Permissions coverage (22 findings vs tfsec's 10) and Compliance/Best Practices (26 findings), reflecting its large policy library
- **tfsec** leads on Encryption (7 findings) and Access Control (12 findings), providing the best AWS infrastructure security signal for Terraform
- **Terrascan** is the only tool with strong compliance framework mapping (PCI-DSS, HIPAA), making it essential for regulated environments despite its lower raw finding counts
- **No tool detected Supply Chain issues in Terraform or Pulumi**; only KICS flagged the unpinned package version in Ansible

---

### 3.3 Tool Selection Guide

**Use tfsec when:**
- Your stack is Terraform-only and you need fast, low-noise scanning in CI/CD
- You want inline code annotations and direct links to remediation documentation
- Pipeline speed matters more than maximum coverage

**Use Checkov when:**
- You need the broadest possible coverage for a Terraform codebase
- Your stack includes multiple IaC frameworks (Terraform + CloudFormation + Kubernetes + Docker)
- Policy-as-code customization is important for organizational standards

**Use Terrascan when:**
- Compliance with specific frameworks (PCI-DSS, HIPAA, SOC2) is a requirement
- You need OPA-based custom policy enforcement
- Audit reports mapped to compliance controls are required

**Use KICS when:**
- Your IaC includes Pulumi or Ansible (no other tool covers these well)
- You want a single tool across multiple frameworks for consistency
- Secrets detection across all file types (YAML, INI, Python) is a priority

---

### 3.4 CI/CD Integration Strategy

A practical multi-stage pipeline should use tools at the appropriate stage to balance speed, coverage, and noise:

```
┌─────────────────────────────────────────────────────┐
│  Stage 1 — Pre-commit (developer machine)           │
│  Tool: tfsec + KICS                                 │
│  Goal: Fast feedback, block obvious misconfigs      │
│  Fail on: CRITICAL and HIGH severity only           │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│  Stage 2 — Pull Request CI                          │
│  Tools: Checkov + KICS                              │
│  Goal: Comprehensive coverage before merge          │
│  Fail on: CRITICAL, HIGH, MEDIUM                    │
│  Output: SARIF → GitHub Security tab                │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│  Stage 3 — Pre-deployment (main branch)             │
│  Tools: Terrascan (compliance) + Checkov            │
│  Goal: Compliance gate before production deploy     │
│  Fail on: Any compliance framework violation        │
│  Output: Compliance report for audit trail          │
└─────────────────────────────────────────────────────┘
```

**Rationale:**
- Pre-commit uses tfsec (fast) + KICS (secrets) to catch issues before they enter version control
- PR stage uses Checkov (broadest coverage) to ensure nothing significant is merged
- Pre-deployment uses Terrascan to enforce compliance controls required for production

---

### 3.5 Lessons Learned

**1. No single tool provides complete coverage.** The three Terraform tools found 53, 78, and 22 findings respectively from the same codebase. Each tool uses a different rule set and scoring approach, meaning critical issues found by one may be completely missed by another. This mirrors the SBOM lab finding where Grype and Trivy had only 17% CVE overlap.

**2. Finding count is not a quality metric.** Checkov's 78 findings vs Terrascan's 22 does not mean Checkov is better — it means Checkov checks more things, including stylistic best practices that may not represent real security risk. For a CI/CD pipeline, Terrascan's focused, lower-noise output may be more actionable.

**3. Secrets are everywhere in IaC.** KICS found hardcoded credentials in all three Ansible files and in the Pulumi YAML. This is the most critical finding category across the entire lab because secrets committed to version control are effectively permanent — even after deletion, they persist in git history and any clones made before removal.

**4. Declarative vs. programmatic IaC have different risk profiles.** Pulumi's Python `__main__.py` can hide secrets in computed variables that static YAML scanners cannot detect. Full Pulumi coverage requires combining KICS (for YAML manifests) with a code-focused secrets scanner (Semgrep, Gitleaks) for the Python layer.

**5. Tool maintenance matters.** tfsec announced it is joining the Trivy project — new development is being directed at Trivy rather than tfsec. For long-term pipeline stability, migrating Terraform scanning to `trivy config` is recommended, as it will receive continued investment and feature development.

---

## Appendix — Commands Reference

```powershell
# tfsec
docker run --rm -v "${PWD}/labs/lab6/vulnerable-iac/terraform:/src" `
  aquasec/tfsec:latest /src --format json | Out-File -Encoding utf8 labs/lab6/analysis/tfsec-results.json

# Checkov
docker run --rm -v "${PWD}/labs/lab6/vulnerable-iac/terraform:/tf" `
  bridgecrew/checkov:latest -d /tf --framework terraform `
  -o json | Out-File -Encoding utf8 labs/lab6/analysis/checkov-terraform-results.json

# Terrascan
docker run --rm -v "${PWD}/labs/lab6/vulnerable-iac/terraform:/iac" `
  tenable/terrascan:latest scan -i terraform -d /iac `
  -o json | Out-File -Encoding utf8 labs/lab6/analysis/terrascan-results.json

# KICS — Pulumi
docker run -t --rm -v "${PWD}/labs/lab6/vulnerable-iac/pulumi:/src" `
  checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html

# KICS — Ansible
docker run -t --rm -v "${PWD}/labs/lab6/vulnerable-iac/ansible:/src" `
  checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html

# Gitleaks — Pulumi Python secrets scan
docker run --rm -v "${PWD}/labs/lab6/vulnerable-iac/pulumi:/src" `
  zricethezav/gitleaks:latest detect --source /src --no-git `
  --report-format json --report-path /src/gitleaks-report.json --exit-code 0
```

### Tools and Versions

- **tfsec** `aquasec/tfsec:latest` — Terraform-specific SAST scanner (transitioning to Trivy)
- **Checkov** `bridgecrew/checkov:latest` — Policy-as-code multi-framework scanner
- **Terrascan** `tenable/terrascan:latest` — OPA-based compliance-focused scanner
- **KICS** `checkmarx/kics:latest` — Open-source multi-framework IaC scanner with first-class Pulumi and Ansible support
- **Gitleaks** `zricethezav/gitleaks:latest` — Secrets scanner used to supplement KICS on the Pulumi Python file