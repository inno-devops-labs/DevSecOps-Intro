# Lab 6 — IaC Security Scanning & Comparative Analysis

**Branch:** `feature/lab6`

---

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1 Setup

```bash
mkdir -p labs/lab6/analysis
```

### 1.2 tfsec Scan

```bash
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src \
  --format json > labs/lab6/analysis/tfsec-results.json

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src > labs/lab6/analysis/tfsec-report.txt
```

**Results:** 53 findings

| Severity | Count |
|----------|-------|
| CRITICAL | 9 |
| HIGH | 25 |
| MEDIUM | 11 |
| LOW | 8 |

### 1.3 Checkov Scan

```bash
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  bridgecrew/checkov:latest \
  -d /tf --framework terraform \
  -o json > labs/lab6/analysis/checkov-terraform-results.json

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  bridgecrew/checkov:latest \
  -d /tf --framework terraform \
  --compact > labs/lab6/analysis/checkov-terraform-report.txt
```

**Results:** 78 findings (most of all three tools)

Top failed checks:
- `CKV_AWS_16` — RDS not encrypted at rest
- `CKV_AWS_17` — RDS publicly accessible
- `CKV_AWS_63` — IAM allows wildcard `*` actions
- `CKV_AWS_62` — full `*:*` admin privileges
- `CKV_AWS_133` — no RDS backup policy
- `CKV_AWS_28` — DynamoDB point-in-time recovery disabled

### 1.4 Terrascan Scan

```bash
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac \
  tenable/terrascan:latest scan \
  -i terraform -d /iac \
  -o json > labs/lab6/analysis/terrascan-results.json

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac \
  tenable/terrascan:latest scan \
  -i terraform -d /iac \
  -o human > labs/lab6/analysis/terrascan-report.txt
```

**Results:** 22 findings

| Severity | Count |
|----------|-------|
| HIGH | 14 |
| MEDIUM | 8 |

Top violations:
- `portWideOpenToPublic` — security groups open to all
- `port22OpenToInternet` — SSH exposed to internet
- `port3389OpenToInternet` — RDP exposed to internet
- `rdsBackupDisabled` — RDS has no backup
- `allUsersReadAccess` — S3 public read access
- `s3Versioning` — S3 versioning not enabled

### 1.5 Terraform Tool Comparison

```bash
echo "=== Terraform Security Analysis ===" > labs/lab6/analysis/terraform-comparison.txt
tfsec_count=$(jq '.results | length' labs/lab6/analysis/tfsec-results.json)
checkov_count=$(jq '.summary.failed' labs/lab6/analysis/checkov-terraform-results.json)
terrascan_count=$(jq '.results.scan_summary.violated_policies' labs/lab6/analysis/terrascan-results.json)
echo "tfsec findings: $tfsec_count" >> labs/lab6/analysis/terraform-comparison.txt
echo "Checkov findings: $checkov_count" >> labs/lab6/analysis/terraform-comparison.txt
echo "Terrascan findings: $terrascan_count" >> labs/lab6/analysis/terraform-comparison.txt
```

Results saved to `labs/lab6/analysis/terraform-comparison.txt`:
- tfsec: **53** findings
- Checkov: **78** findings
- Terrascan: **22** findings

Checkov found the most because it runs 1000+ checks out of the box. tfsec focused on Terraform-specific issues. Terrascan had fewest results but grouped things by category nicely.

### 1.6 Pulumi Scan with KICS

```bash
docker run -t --rm \
  -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src \
  -v "$(pwd)/labs/lab6/analysis":/output \
  checkmarx/kics:latest \
  scan -p /src -o /output --report-formats json,html --output-name kics-pulumi

docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src \
  checkmarx/kics:latest \
  scan -p /src --minimal-ui > labs/lab6/analysis/kics-pulumi-report.txt 2>&1 || true
```

**Results:** 6 findings in `Pulumi-vulnerable.yaml`

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |

Findings:
- **CRITICAL** — RDS DB Instance Publicly Accessible (`publiclyAccessible: true`)
- **HIGH** — DynamoDB Table Not Encrypted
- **HIGH** — Hardcoded password in `Pulumi.yaml` config
- **MEDIUM** — EC2 Instance Monitoring Disabled
- **INFO** — DynamoDB Point-in-Time Recovery Disabled
- **INFO** — EC2 Not EBS Optimized

Pulumi analysis saved to `labs/lab6/analysis/pulumi-analysis.txt`.

### Terraform vs. Pulumi Comparison

The Terraform code had many more findings (53–78) because it's a bigger file set (5 files vs. 1 YAML). The Pulumi YAML file had 6 detected issues but the Python `__main__.py` file was not scanned by KICS (KICS focuses on YAML). Both had the same types of problems — public databases, unencrypted storage, hardcoded secrets.

The key difference is that Pulumi YAML lets you catch issues in the same way as Terraform HCL, but the Python-based Pulumi code is harder to scan with IaC tools — those need SAST tools instead.

### KICS Pulumi Support Evaluation

KICS detected Pulumi YAML automatically and applied AWS-specific queries. It correctly caught the most dangerous issue (publicly accessible RDS). However, it only scanned the YAML manifest — the Python file was ignored. KICS is good for Pulumi YAML but misses programmatic infrastructure logic written in Python.

### Critical Findings (Top 5)

1. **RDS Publicly Accessible (Pulumi)** — `publiclyAccessible: true` exposes the database to the internet. Anyone can try to connect. Fix: set to `false`.

2. **Security Groups Open to 0.0.0.0/0 (Terraform)** — SSH (22), RDP (3389), all ports open to the whole internet. An attacker can brute-force or exploit services. Fix: restrict to specific IP ranges.

3. **Hardcoded Credentials (Terraform + Pulumi)** — DB passwords and API keys written directly in code. If the repo leaks, all credentials are exposed. Fix: use AWS Secrets Manager or Ansible Vault.

4. **RDS Not Encrypted at Rest (Terraform)** — `storage_encrypted = false` means database files are stored as plain text. Fix: set `storage_encrypted = true`.

5. **IAM Wildcard Permissions (Terraform)** — Policies with `Action: "*"` and `Resource: "*"` give full AWS access. A compromised service can do anything. Fix: apply least privilege — only the exact actions needed.

---

## Task 2 — Ansible Security Scanning with KICS

### 2.1 Scan Ansible Playbooks

```bash
docker run -t --rm \
  -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src \
  -v "$(pwd)/labs/lab6/analysis":/output \
  checkmarx/kics:latest \
  scan -p /src -o /output --report-formats json,html --output-name kics-ansible

docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src \
  checkmarx/kics:latest \
  scan -p /src --minimal-ui > labs/lab6/analysis/kics-ansible-report.txt 2>&1 || true
```

**Results:** 10 findings

| Severity | Count |
|----------|-------|
| HIGH | 9 |
| LOW | 1 |

KICS detected these query categories:
- **Passwords And Secrets — Generic Password** (HIGH, 6 files) — plaintext passwords in deploy.yml, configure.yml, inventory.ini
- **Passwords And Secrets — Generic Secret** (HIGH, 1 file) — API keys hardcoded
- **Passwords And Secrets — Password in URL** (HIGH, 2 files) — passwords embedded in connection strings
- **Unpinned Package Version** (LOW, 1 file) — packages without pinned versions

Ansible analysis saved to `labs/lab6/analysis/ansible-analysis.txt`.

### 2.2 Ansible Security Issues

**Key Security Problems:**

1. **Hardcoded passwords in playbooks** — `db_password: supersecret123` written directly in `deploy.yml`. Any developer with repo access sees this. Fix: use `ansible-vault encrypt_string` to store secrets encrypted, then reference them with `{{ vault_db_password }}`.

2. **Credentials in inventory file** — `inventory.ini` has `ansible_ssh_pass=password123` in plain text. Fix: use SSH keys instead of passwords, and never store credentials in the inventory file.

3. **Passwords in connection URLs** — database URLs like `postgres://admin:password@host/db` expose credentials in connection strings. Fix: use environment variables or AWS Secrets Manager.

**Best Practice Violations (3 examples):**

1. **Missing `no_log: true` on sensitive tasks** — Tasks that handle passwords or tokens should have `no_log: true` to prevent secrets from appearing in Ansible logs. Without it, anyone who reads the playbook output can see sensitive values.

2. **Using `shell` instead of modules** — When a task uses `shell: apt-get install -y {{ package }}` with user-provided variables, it can lead to command injection. Use the `apt` module with `name: "{{ package }}"` instead.

3. **Overly permissive file permissions** — Setting `mode: '0777'` on config files allows any user on the system to read, write, and execute them. Use `0644` for config files and `0600` for private keys.

**Remediation Steps:**

```yaml
# Before (vulnerable)
vars:
  db_password: supersecret123

# After (secure)
vars:
  db_password: "{{ vault_db_password }}"
```

```bash
# Encrypt the password with Ansible Vault
ansible-vault encrypt_string 'supersecret123' --name 'vault_db_password'
```

```yaml
# Before (no_log missing)
- name: Set database password
  command: mysql -u root -p{{ db_password }} -e "ALTER USER..."

# After (secure)
- name: Set database password
  command: mysql -u root -p{{ db_password }} -e "ALTER USER..."
  no_log: true
```

```ini
# Before (credentials in inventory)
[webservers]
192.168.1.1 ansible_ssh_pass=password123

# After (use SSH keys)
[webservers]
192.168.1.1 ansible_ssh_private_key_file=~/.ssh/id_rsa
```

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 16 (6 Pulumi + 10 Ansible) |
| **Scan Speed** | Fast | Slow | Medium | Medium |
| **False Positives** | Low | Medium | Low | Low |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Platform Support** | Terraform only | Terraform, CF, K8s, Docker | Terraform, K8s, Helm | Terraform, Pulumi, Ansible, CF, K8s |
| **Output Formats** | JSON, text, SARIF, JUnit | JSON, CLI, SARIF, JUnit | JSON, YAML, XML, human | JSON, HTML, SARIF, JUnit |
| **CI/CD Integration** | Easy | Easy | Medium | Easy |
| **Unique Strengths** | Terraform-specific, fast | Most checks, multi-framework | OPA-based, compliance | Pulumi + Ansible support |

### 3.2 Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|-------|---------|-----------|---------------|----------------|----------|
| **Encryption Issues** | ✅ High | ✅ High | ✅ Medium | ✅ Critical/High | N/A | Checkov |
| **Network Security** | ✅ Critical | ✅ High | ✅ High | ✅ N/A | N/A | tfsec |
| **Secrets Management** | ⚠️ Partial | ✅ Good | ⚠️ Partial | ✅ High | ✅ High | KICS |
| **IAM/Permissions** | ✅ High | ✅ High | ✅ Medium | N/A | N/A | Checkov |
| **Access Control** | ✅ Critical | ✅ High | ✅ High | ✅ Critical | N/A | tfsec |
| **Compliance/Best Practices** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | Checkov |

### 3.3 Top 5 Critical Findings with Remediation

**1. Security Group Open to the Internet (Terraform — tfsec AVD-AWS-0107, CRITICAL)**

All ingress traffic is allowed from `0.0.0.0/0`. An attacker can probe any service.

```hcl
# Vulnerable
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # anyone in the world
}

# Fixed
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # internal network only
}
```

**2. RDS Publicly Accessible (Pulumi — KICS CRITICAL)**

Database is reachable from the internet (`publiclyAccessible: true`). A leaked password means instant database compromise.

```yaml
# Vulnerable
publiclyAccessible: true

# Fixed
publiclyAccessible: false
```

**3. Hardcoded Database Password (Pulumi — KICS HIGH)**

Password in plain text in the YAML config file. Anyone who sees the code or the file system gets the credentials.

```yaml
# Vulnerable
config:
  dbPassword: "admin123"

# Fixed
config:
  dbPassword:
    secret: true  # use Pulumi secret - value stored encrypted
```

**4. No Encryption at Rest for RDS (Terraform — Checkov CKV_AWS_16, HIGH)**

If the EBS volume or database is ever accessed physically (e.g., snapshot leak), data is readable.

```hcl
# Vulnerable
resource "aws_db_instance" "example" {
  storage_encrypted = false
}

# Fixed
resource "aws_db_instance" "example" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}
```

**5. IAM Wildcard Permissions (Terraform — Checkov CKV_AWS_63, HIGH)**

A policy that allows `Action: "*"` on `Resource: "*"` gives full AWS control. If that role is compromised, the attacker can delete everything.

```hcl
# Vulnerable
statement {
  actions   = ["*"]
  resources = ["*"]
  effect    = "Allow"
}

# Fixed
statement {
  actions   = ["s3:GetObject", "s3:PutObject"]
  resources = ["arn:aws:s3:::my-bucket/*"]
  effect    = "Allow"
}
```

### 3.4 Tool Selection Guide

| Use Case | Recommended Tool | Reason |
|----------|-----------------|--------|
| Fast feedback in PR/commit hooks | tfsec | Very fast, Terraform-specific, low noise |
| Comprehensive Terraform audit | Checkov | 1000+ checks, catches the most issues |
| Compliance scanning (PCI-DSS, HIPAA) | Terrascan | Maps violations to compliance frameworks |
| Pulumi YAML scanning | KICS | Only tool with first-class Pulumi support |
| Ansible playbook security | KICS | Dedicated Ansible query catalog |
| Multi-framework projects | Checkov or KICS | Both support multiple IaC types |

### 3.5 Lessons Learned

1. **No single tool is enough.** tfsec (53), Checkov (78), and Terrascan (22) all scanned the same Terraform code but got very different numbers. Checkov found 78 because it checks operational best practices (monitoring, backups) — not just pure security. tfsec focused on real risks. Terrascan was the fastest but least thorough.

2. **KICS is unique for Pulumi and Ansible.** The other three tools do not support Pulumi or Ansible at all. KICS is the go-to choice when you have non-Terraform IaC.

3. **False positives exist.** Checkov flagged missing Multi-AZ and enhanced monitoring as failures — these are best practices, not security bugs. This creates noise. tfsec had less noise because it focuses on security-specific rules.

4. **Python-based Pulumi is invisible to IaC scanners.** All tools only scanned the YAML files. The Python `__main__.py` in Pulumi needs a SAST tool (like Semgrep from Lab 5), not an IaC scanner. This is an important gap to know.

5. **Secrets are everywhere and hard to catch completely.** KICS found hardcoded secrets in Ansible and Pulumi YAML. tfsec and Checkov also detected some. But none of the tools caught everything — secret scanning tools like `truffleHog` or `detect-secrets` should be added on top.

### 3.6 CI/CD Integration Strategy

A good pipeline scans at multiple stages to catch different issues:

```yaml
# Example CI/CD pipeline stages

stages:
  - pre-commit:           # Before code is committed
      - tfsec             # Fast Terraform checks
      - detect-secrets    # Catch hardcoded credentials

  - pull-request:         # On every PR
      - tfsec             # Terraform security
      - checkov           # Full Terraform compliance
      - kics              # Pulumi + Ansible scanning

  - pre-deploy:           # Before deploying to prod
      - terrascan         # Compliance framework check (PCI, HIPAA)
      - checkov           # Full audit with all checks enabled
```

**Why this approach:**
- Pre-commit hooks give fast feedback with no context switching — the developer fixes it immediately
- PR checks are more thorough and block merges if critical issues are found
- Pre-deploy is the last line of defense — slower tools like Terrascan run here
- Running all tools at every stage would be too slow and annoying

**Threshold recommendations:**
- Block on CRITICAL and HIGH severity issues
- Report but do not block on MEDIUM (review manually)
- Ignore LOW and INFO in automated pipelines (too much noise)
