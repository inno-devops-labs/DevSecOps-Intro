# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Task 1 — Terraform & Pulumi Security Scanning (5 pts)

### Terraform Tool Comparison

Three tools were used to scan the vulnerable Terraform code in `labs/lab6/vulnerable-iac/terraform/`:

| Tool | Total Findings |
|------|---------------|
| **tfsec** | 53 |
| **Checkov** | 78 |
| **Terrascan** | 22 |

**tfsec** produced 53 findings with the following severity breakdown:
- CRITICAL: 9 (mostly security groups allowing 0.0.0.0/0 and publicly accessible RDS)
- HIGH: 25 (S3 encryption, IAM wildcards, database misconfigurations)
- MEDIUM: 11 (logging, monitoring gaps)
- LOW: 8 (best practice violations)

By service category (tfsec):
- S3: 18 findings (public ACLs, missing encryption, no versioning, no access logging)
- RDS: 11 findings (unencrypted storage, public access, no backups, weak passwords)
- EC2/Security Groups: 11 findings (0.0.0.0/0 ingress/egress rules)
- IAM: 10 findings (wildcard permissions, privilege escalation)
- DynamoDB: 3 findings (no encryption, no point-in-time recovery)

**Checkov** found the most issues (78) because it includes compliance-focused checks that other tools miss, such as:
- `CKV_AWS_273` — SSO-based access instead of IAM users
- `CKV2_AWS_61` — S3 lifecycle configuration
- `CKV2_AWS_62` — S3 event notifications
- `CKV2_AWS_30` — PostgreSQL query logging
- `CKV2_AWS_60` — RDS copy tags to snapshots
- `CKV_AWS_144` — S3 cross-region replication

**Terrascan** found 22 violations, categorized by domain:
- Data Protection: 7 (encryption, versioning)
- Infrastructure Security: 6 (open ports, security groups)
- Identity and Access Management: 4 (inline policies, wildcard permissions)
- Resilience: 3 (backups, point-in-time recovery)
- Logging and Monitoring: 2 (RDS log exports)

**Effectiveness Comparison:** Checkov's policy-as-code approach produces the most comprehensive results. tfsec provides a strong balance of coverage and low false positives. Terrascan is the most focused, detecting fewer issues but mapping them to compliance categories (useful for audits).

### Pulumi Security Analysis (KICS)

KICS scanned `labs/lab6/vulnerable-iac/pulumi/Pulumi-vulnerable.yaml` and found **6 findings**:

| Severity | Finding | CWE |
|----------|---------|-----|
| **CRITICAL** | RDS DB Instance Publicly Accessible | CWE-284 |
| **HIGH** | DynamoDB Table Not Encrypted | CWE-311 |
| **HIGH** | Passwords And Secrets - Generic Password (hardcoded `dbPassword`) | CWE-798 |
| **MEDIUM** | EC2 Instance Monitoring Disabled | CWE-778 |
| **INFO** | DynamoDB Table Point In Time Recovery Disabled | CWE-459 |
| **INFO** | EC2 Not EBS Optimized | CWE-459 |

The CRITICAL finding was the RDS instance with `publiclyAccessible: true` at line 104 of `Pulumi-vulnerable.yaml`, which exposes the database to the public internet — a severe risk for data breaches.

### Terraform vs. Pulumi Comparison

The same types of security issues appear in both Terraform (HCL) and Pulumi (YAML): public databases, unencrypted storage, hardcoded credentials, and open security groups. However, there is a significant tooling gap:

- **Terraform** has 3+ mature scanning tools that collectively found 153 findings across the same vulnerable patterns
- **Pulumi** currently has fewer scanning options; KICS detected 6 findings from the YAML manifest

This difference is partly because Terraform scanners can parse HCL deeply and have large rule catalogs built over years. KICS's Pulumi support (added in v1.6.x) is newer but provides essential coverage for critical issues.

### KICS Pulumi Support Evaluation

KICS's Pulumi-specific query catalog correctly detected:
- Encryption issues (DynamoDB without server-side encryption)
- Access control (publicly accessible RDS)
- Secrets management (hardcoded passwords in config)
- Monitoring gaps (EC2 detailed monitoring disabled)
- Resilience (PITR disabled)

Strengths: Auto-detects Pulumi YAML, provides CWE mappings, generates JSON/HTML/console reports. Limitation: Only scans Pulumi YAML format, not Python/TypeScript Pulumi code.

### Top 5 Critical Findings (Task 1)

**1. Hardcoded AWS Credentials (Terraform `main.tf:8-9`)**
```hcl
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```
Detected by: tfsec, Checkov (`CKV_AWS_41`). Remediation: Use environment variables, AWS profiles, or IAM instance roles.

**2. Publicly Accessible RDS with No Encryption (Terraform `database.tf:15-17`, Pulumi `Pulumi-vulnerable.yaml:103-104`)**
```hcl
storage_encrypted   = false
publicly_accessible = true
```
Detected by: All tools. Remediation: Set `storage_encrypted = true`, `publicly_accessible = false`, and use private subnets.

**3. Security Group Allowing All Traffic from 0.0.0.0/0 (Terraform `security_groups.tf:10-16`)**
```hcl
ingress {
  from_port   = 0
  to_port     = 65535
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}
```
Detected by: tfsec (CRITICAL), Checkov, Terrascan. Remediation: Restrict CIDR blocks to specific IPs/subnets and limit to required ports only.

**4. Wildcard IAM Permissions (Terraform `iam.tf`)**
```hcl
actions   = ["*"]
resources = ["*"]
```
Detected by: tfsec, Checkov (`CKV_AWS_62`, `CKV_AWS_63`, `CKV_AWS_286`), Terrascan. Remediation: Apply least-privilege — grant only specific actions on specific resources.

**5. Public S3 Bucket with Public ACL (Terraform `main.tf:15`)**
```hcl
acl = "public-read"
```
Detected by: tfsec, Checkov (`CKV_AWS_20`), Terrascan (`allUsersReadAccess`). Remediation: Set ACL to `private`, enable `aws_s3_bucket_public_access_block` with all flags set to `true`.

---

## Task 2 — Ansible Security Scanning with KICS (2 pts)

### Ansible Security Issues

KICS scanned `labs/lab6/vulnerable-iac/ansible/` and found **10 findings** (9 HIGH, 1 LOW):

| Severity | Finding | Count | Files |
|----------|---------|-------|-------|
| HIGH | Passwords And Secrets - Generic Password | 6 | deploy.yml, configure.yml, inventory.ini |
| HIGH | Passwords And Secrets - Password in URL | 2 | deploy.yml |
| HIGH | Passwords And Secrets - Generic Secret | 1 | inventory.ini |
| LOW | Unpinned Package Version | 1 | deploy.yml |

### Best Practice Violations (3 violations with security impact)

**1. Hardcoded Credentials Throughout Playbooks (CWE-798)**

Plaintext passwords appear in `deploy.yml` (lines 12, 14, 16), `configure.yml` (line 16), and `inventory.ini` (lines 5, 6, 10, 18-20):

```yaml
# deploy.yml
db_password: "SuperSecret123!"
api_key: "sk_live_1234567890abcdef"
db_connection: "postgresql://admin:password123@db.example.com:5432/myapp"
```

```ini
# inventory.ini
web1.example.com ansible_user=root ansible_password=P@ssw0rd123!
db1.example.com ansible_user=root ansible_password=DBr00tP@ss!
```

**Security impact:** Anyone with read access to the repository or playbook output can extract production credentials. Credentials in version control persist in git history even after removal.

**2. Credentials Embedded in URLs (CWE-798)**

```yaml
# deploy.yml:16
db_connection: "postgresql://admin:password123@db.example.com:5432/myapp"

# deploy.yml:72
repo: 'https://username:password@github.com/company/repo.git'
```

**Security impact:** Credentials in URLs often end up in logs, browser history, HTTP referer headers, and monitoring systems. The git clone URL with credentials will appear in process listings.

**3. Unpinned Package Version (CWE-706)**

```yaml
# deploy.yml:99
state: latest
```

**Security impact:** Using `state: latest` makes builds non-deterministic. A compromised package mirror could serve a malicious version, and there is no guarantee that the deployed version matches what was tested.

### KICS Ansible Queries Evaluation

KICS focused heavily on **secrets detection** for Ansible, catching 9 out of 10 findings in the secrets management category. This is appropriate since hardcoded secrets are the most critical Ansible security risk. However, KICS did not detect several other issues present in the code:

- Shell injection risks (`shell: rm -rf {{ user_input }}/*`)
- Overly permissive file permissions (`mode: '0777'`)
- Disabled firewall (`ufw` stopped)
- Disabled SELinux
- Weak SSH configuration (PermitRootLogin yes, PermitEmptyPasswords yes)
- Missing `no_log: true` on sensitive tasks
- Downloading scripts over HTTP without checksum verification

This suggests KICS's Ansible scanning is strong for secrets but would benefit from being paired with Ansible-specific linters like `ansible-lint` for broader coverage.

### Remediation Steps

**For hardcoded credentials:**
```yaml
# Use Ansible Vault for secrets
ansible-vault encrypt vars/secrets.yml

# Reference vault-encrypted variables
vars_files:
  - vars/secrets.yml   # encrypted with ansible-vault

# Or use environment variables
db_password: "{{ lookup('env', 'DB_PASSWORD') }}"
```

**For inventory credentials:**
```ini
# Use SSH keys instead of passwords
[webservers]
web1.example.com ansible_user=deploy ansible_ssh_private_key_file=~/.ssh/deploy_key

# Or use ansible-vault encrypted inventory variables
[all:vars]
ansible_become_password={{ vault_become_password }}
```

**For URL-embedded credentials:**
```yaml
# Use separate auth variables from vault
- name: Clone repository
  git:
    repo: "https://github.com/company/repo.git"
    dest: /var/www/myapp
  environment:
    GIT_ASKPASS: /usr/local/bin/git-credential-helper
```

**For unpinned packages:**
```yaml
- name: Install application
  apt:
    name: myapp=1.2.3-1  # Pin specific version
    state: present
```

---

## Task 3 — Comparative Tool Analysis & Security Insights (3 pts)

### Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 16 (6 Pulumi + 10 Ansible) |
| **Scan Speed** | Fast (~3s) | Medium (~8s) | Medium (~5s) | Medium (~5s) |
| **False Positives** | Low | Medium | Low | Low |
| **Report Quality** | 4/5 | 4/5 | 3/5 | 5/5 (HTML+JSON) |
| **Ease of Use** | 5/5 | 4/5 | 3/5 | 4/5 |
| **Documentation** | 4/5 | 5/5 | 3/5 | 4/5 |
| **Platform Support** | Terraform only | Terraform, K8s, Docker, CF | Terraform, K8s, Docker | Terraform, Pulumi, Ansible, K8s, Docker, CF |
| **Output Formats** | JSON, text, SARIF, CSV | JSON, CLI, SARIF, JUnit | JSON, human, YAML, XML | JSON, HTML, SARIF, console |
| **CI/CD Integration** | Easy (exit codes) | Easy (built-in) | Medium | Easy (exit codes + formats) |
| **Unique Strengths** | Terraform-focused depth, very fast | Largest rule set, policy-as-code | Compliance framework mapping (PCI-DSS, HIPAA) | Multi-framework (Pulumi, Ansible), CWE mapping |

### Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|-------|---------|-----------|---------------|----------------|-----------|
| **Encryption Issues** | 8 | 6 | 7 | 1 | N/A | tfsec |
| **Network Security** | 17 | 14 | 6 | 0 | 0 | tfsec |
| **Secrets Management** | 4 | 1 | 0 | 1 | 9 | KICS |
| **IAM/Permissions** | 10 | 20 | 4 | 0 | 0 | Checkov |
| **Access Control** | 6 | 8 | 3 | 1 | 0 | Checkov |
| **Compliance/Best Practices** | 8 | 29 | 2 | 3 | 1 | Checkov |

**Key observations:**
- **tfsec** excels at network security (17 findings) — it deeply analyzes security group rules and CIDR blocks
- **Checkov** dominates IAM/permissions (20 findings) and compliance (29 findings) — its policy catalog is the most extensive
- **Terrascan** is balanced but has fewer rules overall — its strength is compliance framework mapping
- **KICS** is the only tool that caught secrets in Ansible (9 findings) and provides Pulumi scanning

### Top 5 Critical Findings (Across All Frameworks)

1. **Hardcoded AWS Access Keys** (Terraform `main.tf:8-9`) — Complete account compromise if leaked. Detected by tfsec + Checkov.

2. **Publicly Accessible RDS with Disabled Encryption** (Terraform `database.tf:15-17`, Pulumi `Pulumi-vulnerable.yaml:103-104`) — Database exposed to internet without encryption. Detected by all tools.

3. **Security Group Allowing All Traffic** (Terraform `security_groups.tf:10-16`) — All ports open to 0.0.0.0/0 = no network boundary. Detected by tfsec (CRITICAL) + Checkov + Terrascan.

4. **Plaintext Credentials in Ansible Inventory** (`inventory.ini:5,6,10,18-20`) — Root passwords and API keys in plaintext. Detected by KICS (HIGH).

5. **Wildcard IAM Policy** (Terraform `iam.tf`) — `"*"` actions on `"*"` resources = full admin. Detected by tfsec + Checkov (`CKV_AWS_62`, `CKV_AWS_286`) + Terrascan.

### Tool Selection Guide

| Use Case | Recommended Tool(s) | Justification |
|----------|---------------------|---------------|
| **Terraform-only project** | tfsec + Checkov | tfsec for fast CI checks, Checkov for comprehensive coverage |
| **Multi-framework (TF + Pulumi + Ansible)** | Checkov + KICS | Broad coverage across all IaC types |
| **Compliance audit (PCI-DSS, HIPAA)** | Terrascan | Built-in compliance framework mapping |
| **Pre-commit hook (fast feedback)** | tfsec | Fastest scan time, low false positives |
| **Secrets detection across IaC** | KICS | Best secrets detection across Pulumi and Ansible |
| **Maximum coverage** | All four tools | Each tool finds unique issues others miss |

### Lessons Learned

1. **No single tool catches everything.** Checkov found 78 issues, tfsec found 53, Terrascan found 22 — but each detected unique issues the others missed. For example, only Checkov flagged `CKV_AWS_273` (SSO vs IAM users) and only Terrascan explicitly categorized findings by compliance frameworks.

2. **Secrets detection varies significantly.** KICS caught 9 hardcoded secrets in Ansible that Terraform-focused tools cannot scan. Checkov only flagged 1 secret (the AWS access key). Organizations need dedicated secrets scanning in addition to IaC scanning.

3. **Tool maturity matters for newer frameworks.** Terraform has the richest ecosystem (3 tools, 153 combined findings). Pulumi scanning is still maturing — KICS found 6 issues but likely missed others that Terraform tools would catch on equivalent HCL code.

4. **False positives need management.** Checkov's higher finding count (78) includes some checks that may not apply to every context (e.g., cross-region replication for a dev environment). Teams need to configure baseline suppressions.

5. **Exit code behavior differs.** tfsec, Checkov, and KICS exit with non-zero codes when findings exist. This is useful for CI/CD gates but requires `|| true` or `--ignore-on-exit` for report generation scripts.

### CI/CD Integration Strategy

A recommended multi-stage pipeline:

```
Stage 1: Pre-commit (Developer Workstation)
  - tfsec (fast, low false positives)
  - Purpose: Catch obvious issues before code reaches the repository

Stage 2: PR Validation (CI Pipeline)
  - Checkov (comprehensive Terraform + multi-framework)
  - KICS (Pulumi + Ansible scanning)
  - Gate: Block merge on CRITICAL/HIGH findings

Stage 3: Scheduled Compliance Scan (Nightly)
  - Terrascan with compliance frameworks enabled
  - Full scan with all tools for drift detection
  - Purpose: Audit trail and compliance reporting

Stage 4: Pre-deployment (CD Pipeline)
  - Checkov with strict policy (zero tolerance for CRITICAL)
  - KICS for final secrets scan
  - Gate: Block deployment on any CRITICAL finding
```

**Justification:** This layered approach balances developer experience (fast pre-commit checks) with thorough security coverage (comprehensive CI/CD scans). Using multiple tools at different stages prevents alert fatigue while ensuring nothing reaches production unscanned. tfsec is ideal for pre-commit due to its speed; Checkov provides the broadest coverage for PR validation; Terrascan adds compliance context for audits; KICS covers Pulumi and Ansible which the Terraform-specific tools cannot scan.
