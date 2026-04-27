# Lab 6 — IaC Security Scanning & Comparative Analysis

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1 Terraform Tool Comparison

All three tools scanned the same five Terraform files (`main.tf`, `security_groups.tf`, `database.tf`, `iam.tf`, `variables.tf`) containing 30+ intentional vulnerabilities across 16 resources.

| Tool | Total Findings | CRITICAL | HIGH | MEDIUM | LOW |
|------|---------------|----------|------|--------|-----|
| **tfsec** | 53 | 9 | 25 | 11 | 8 |
| **Checkov** | 78 (48 passed) | — | — | — | — |
| **Terrascan** | 22 | 0 | 14 | 8 | 0 |

> Checkov does not expose per-severity counters in its JSON summary for the free tier; severity breakdown is embedded per-check inside `results.failed_checks`.

**tfsec findings by AWS service:**

| Service | Findings |
|---------|----------|
| S3 | 18 |
| RDS | 11 |
| EC2 / Security Groups | 11 |
| IAM | 10 |
| DynamoDB | 3 |

---

### 1.2 Pulumi Security Analysis (KICS)

KICS scanned `Pulumi-vulnerable.yaml` and identified **6 findings** across the YAML-based Pulumi manifest:

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |

**Detailed findings:**

| Finding | Severity | Category |
|---------|----------|----------|
| RDS DB Instance Publicly Accessible | CRITICAL | Insecure Configurations |
| DynamoDB Table Not Encrypted | HIGH | Encryption |
| Passwords And Secrets — Generic Password | HIGH | Secret Management |
| EC2 Instance Monitoring Disabled | MEDIUM | Observability |
| DynamoDB Table Point In Time Recovery Disabled | INFO | Best Practices |
| EC2 Not EBS Optimized | INFO | Best Practices |

KICS auto-detected the Pulumi YAML format without any explicit flag. Its Pulumi query catalog covers AWS, Azure, GCP, and Kubernetes resource types and matches findings directly to named resource blocks in the manifest.

---

### 1.3 Terraform vs. Pulumi — Security Issue Comparison

| Dimension | Terraform (HCL) | Pulumi (YAML) |
|-----------|----------------|---------------|
| Issues detected | 53 (tfsec) / 78 (Checkov) | 6 (KICS) |
| Hardcoded secrets | Yes — in `variables.tf` defaults | Yes — in `Pulumi-vulnerable.yaml` |
| Publicly accessible DB | Yes — `publicly_accessible = true` | Yes — `publiclyAccessible: true` |
| Unencrypted storage | Yes — S3, RDS, DynamoDB | Yes — DynamoDB |
| Open security groups | Yes — 0.0.0.0/0 ingress/egress | Not present in YAML manifest |
| IAM wildcards | Yes — `Action: "*"` | Not defined in YAML manifest |

The lower Pulumi finding count reflects the narrower scope of `Pulumi-vulnerable.yaml` (only a subset of infrastructure is expressed in the YAML manifest vs. the full Terraform codebase). The Python `__main__.py` file was not scanned by KICS because KICS targets Pulumi YAML manifests, not Python SDK code.

---

### 1.4 KICS Pulumi Support Evaluation

KICS v1.6+ provides first-class Pulumi YAML support with a dedicated query catalog. Key observations:

- Auto-detection works reliably — no `--type pulumi` flag needed.
- Query coverage for AWS resource types (RDS, DynamoDB, EC2) is solid.
- The scanner does not process Pulumi Python/Go/TypeScript SDK code — only YAML manifests.
- HTML and JSON output formats are both well-structured and usable for pipeline integration.
- Exit code is non-zero when findings exist (expected behavior); use `|| true` in CI scripts.

---

### 1.5 Critical Terraform Findings (Top 5)

**Finding 1 — Open Security Groups (0.0.0.0/0 ingress + egress)**

- Tool: tfsec (`aws-ec2-no-public-ingress-sgr`, `aws-ec2-no-public-egress-sgr`) — CRITICAL
- Resources: `aws_security_group.allow_all`, `aws_security_group.ssh_open`, `aws_security_group.database_exposed`
- File: `security_groups.tf`
- Impact: Any host on the internet can reach these instances on all ports; data exfiltration is unrestricted.

Remediation:
```hcl
# Replace 0.0.0.0/0 with explicit CIDR blocks
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # Internal network only
}
egress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # HTTPS egress only
}
```

---

**Finding 2 — IAM Wildcard Permissions (`Action: "*"`, `Resource: "*"`)**

- Tool: tfsec (`aws-iam-no-policy-wildcards`) — HIGH; Checkov (`CKV_AWS_355`) — HIGH
- Resource: `aws_iam_policy.admin_policy`, `aws_iam_user_policy.service_policy`
- File: `iam.tf`
- Impact: Any principal with this policy attached becomes an AWS administrator. A compromised credential grants complete account takeover.

Remediation:
```hcl
policy = jsonencode({
  Version = "2012-10-17"
  Statement = [{
    Effect   = "Allow"
    Action   = ["s3:GetObject", "s3:PutObject"]      # Specific actions only
    Resource = "arn:aws:s3:::my-app-bucket/*"         # Specific resource
  }]
})
```

---

**Finding 3 — Publicly Accessible RDS Instance**

- Tool: tfsec (`aws-rds-enable-public-access`) — HIGH; KICS (Pulumi) — CRITICAL
- Resource: `aws_db_instance.unencrypted_db`
- File: `database.tf`
- Impact: Database port (5432/3306) is directly reachable from the internet. Brute-force, credential stuffing, and direct exploitation attacks are trivially possible.

Remediation:
```hcl
resource "aws_db_instance" "app_db" {
  publicly_accessible    = false       # Critical: must be false
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.private.name
}
```

---

**Finding 4 — Unencrypted S3 Buckets (public ACL + no server-side encryption)**

- Tool: tfsec (`aws-s3-enable-bucket-encryption`, `aws-s3-no-public-access-with-acl`) — HIGH; Checkov (`CKV2_AWS_6`) — HIGH
- Resource: `aws_s3_bucket.public_data`, `aws_s3_bucket.unencrypted_data`
- File: `main.tf`
- Impact: Data stored in S3 is readable by anyone on the internet and stored in plaintext. A single bucket misconfiguration can expose an entire data lake.

Remediation:
```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "enc" {
  bucket = aws_s3_bucket.app_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.app_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

---

**Finding 5 — Hardcoded Credentials in variables.tf**

- Tool: Checkov (`CKV_AWS_289`) — HIGH; tfsec — flagged via secrets detection
- Resource: `variables.tf` default values
- File: `variables.tf`
- Impact: Secrets committed to version control are permanent. Even after rotation, the credential exists in git history and any clone of the repository.

Remediation:
```hcl
# variables.tf — no default values for secrets
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
  # No default — must be provided via tfvars or secrets manager
}
```
```bash
# Retrieve at runtime from AWS Secrets Manager
data "aws_secretsmanager_secret_version" "db_pass" {
  secret_id = "prod/app/db_password"
}
```

---

## Task 2 — Ansible Security Scanning (KICS)

### 2.1 Scan Results

KICS scanned `deploy.yml`, `configure.yml`, and `inventory.ini` and identified **10 findings** across 4 unique query types:

| Finding | Severity | Category | Occurrences |
|---------|----------|----------|-------------|
| Passwords And Secrets — Generic Password | HIGH | Secret Management | 6 |
| Passwords And Secrets — Password in URL | HIGH | Secret Management | 2 |
| Passwords And Secrets — Generic Secret | HIGH | Secret Management | 1 |
| Unpinned Package Version | LOW | Supply-Chain | 1 |

All 9 HIGH findings fall into the **Secret Management** category, which reflects the dominant security risk in the provided Ansible code: credentials defined in plaintext across playbook vars, inventory files, and connection strings.

---

### 2.2 Best Practice Violations

**Violation 1 — Hardcoded secrets in playbook `vars` block**

`deploy.yml` defines `db_password: "SuperSecret123!"` and `api_key: "sk_live_1234567890abcdef"` directly in the playbook vars section. Any developer with repo access or any CI/CD log output can read these values.

Impact: Credential exposure via version control, CI logs, and `ansible --list-vars` output.

Fix:
```yaml
# Use Ansible Vault for all secrets
vars_files:
  - vault_secrets.yml   # encrypted with: ansible-vault encrypt vault_secrets.yml

tasks:
  - name: Set database password
    command: mysql -u root -p{{ db_password }} -e "CREATE DATABASE myapp;"
    no_log: true   # Prevent password appearing in logs
```

---

**Violation 2 — Password in database connection URL**

`deploy.yml` sets `db_connection: "postgresql://admin:password123@db.example.com:5432/myapp"` — a URL containing both username and password in plaintext. KICS detects this as "Password in URL" (HIGH). This pattern also causes passwords to appear in process listings (`ps aux`).

Impact: Credential exposed in environment variables, process lists, application logs, and anywhere the connection string is passed.

Fix:
```yaml
vars:
  db_host: "db.example.com"
  db_user: "{{ vault_db_user }}"
  db_password: "{{ vault_db_password }}"

tasks:
  - name: Configure database connection
    template:
      src: db_config.j2
      dest: /etc/myapp/database.conf
      mode: '0600'
    no_log: true
```

---

**Violation 3 — Unpinned package versions**

KICS flagged `apt-get install -y nginx mysql-client` (and similar `shell` module usage) as having unpinned versions. Installing the latest available package at deploy time makes deployments non-reproducible and potentially introduces vulnerable package versions silently.

Impact: Supply-chain risk — a compromised or vulnerable package version can be introduced without any change to the playbook.

Fix:
```yaml
- name: Install packages
  apt:
    name:
      - nginx=1.24.*
      - mysql-client=8.0.*
    state: present
    update_cache: yes
```

---

### 2.3 KICS Ansible Query Evaluation

KICS's Ansible support covers:
- **Secret Management** — detects generic passwords, API keys, tokens, and password-in-URL patterns across all YAML fields.
- **Supply-Chain** — detects unpinned package versions in `apt`, `yum`, `pip` tasks.
- **Command injection risk** — queries for use of `shell`/`command` modules where Ansible-native modules exist.
- **File permissions** — detects world-writable (`0777`) file modes.
- **`no_log` enforcement** — detects sensitive tasks missing `no_log: true`.

A notable gap observed: KICS did not flag the `mode: '0777'` world-writable config file in `deploy.yml`, nor the plaintext credentials in `inventory.ini` beyond the password-in-URL pattern. Tools like `ansible-lint` would catch some of these gaps.

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Tool Effectiveness Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 6 (Pulumi) + 10 (Ansible) |
| **Scan Speed** | Fast | Medium | Medium | Medium |
| **False Positives** | Low | Low-Medium | Low | Low |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Platform Support** | Terraform only | Terraform, CF, K8s, Docker, ARM | Terraform, K8s, Helm | Terraform, Pulumi, Ansible, CF, K8s, Docker |
| **Output Formats** | JSON, text, SARIF, JUnit, HTML | JSON, CLI, SARIF, JUnit, CSV, CycloneDX | JSON, YAML, XML, human | JSON, HTML, SARIF, JUnit, ASFF |
| **CI/CD Integration** | Easy | Easy | Medium | Easy |
| **Unique Strengths** | Speed + Terraform depth | Policy count + multi-framework | OPA + compliance frameworks | Pulumi + Ansible unified |

---

### 3.2 Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|-------|---------|-----------|---------------|----------------|----------|
| **Encryption** | 14 | 18 | 5 | 2 | 0 | Checkov |
| **Network Security** | 11 | 8 | 2 | 0 | 0 | tfsec |
| **Secrets Management** | 0 | 4 | 0 | 1 | 9 | KICS (Ansible) |
| **IAM / Permissions** | 10 | 12 | 0 | 0 | 0 | Checkov |
| **Access Control** | 9 | 10 | 8 | 1 | 0 | Checkov |
| **Compliance / Best Practices** | 9 | 26 | 7 | 2 | 1 | Checkov |

*Counts are approximate — tools categorize findings differently.*

**Key observations:**
- tfsec leads on **network security** (open security groups), detecting 11 EC2/SG issues vs. Checkov's 8 and Terrascan's 2.
- Checkov leads on **IAM and best practices** due to its larger rule set (1000+ policies vs. tfsec's ~150).
- KICS is the only tool detecting **secrets in Ansible** files — other tools don't scan Ansible at all.
- Terrascan detected unique findings around **RDS IAM Authentication** and **S3 versioning** that tfsec missed.
- None of the Terraform tools detected the hardcoded `db_password` default in `variables.tf`; only Checkov flagged it via `CKV_AWS_289`.

---

### 3.3 Top 5 Critical Findings Summary

| # | Finding | Tool(s) | Severity | File |
|---|---------|---------|----------|------|
| 1 | Security groups allow 0.0.0.0/0 ingress + egress | tfsec, Checkov, Terrascan | CRITICAL | `security_groups.tf` |
| 2 | IAM wildcard `Action: "*"` on `Resource: "*"` | tfsec, Checkov | HIGH | `iam.tf` |
| 3 | RDS instance publicly accessible (`publicly_accessible = true`) | tfsec, Checkov, KICS | CRITICAL/HIGH | `database.tf`, `Pulumi-vulnerable.yaml` |
| 4 | S3 bucket with public ACL and no encryption | tfsec, Checkov, Terrascan | HIGH | `main.tf` |
| 5 | Hardcoded passwords in Ansible playbook vars | KICS | HIGH | `deploy.yml` |

---

### 3.4 Tool Selection Guide

| Use Case | Recommended Tool | Reason |
|----------|-----------------|--------|
| Terraform-only project, fast CI gate | **tfsec** | Fastest scan, lowest false positives, Terraform-native |
| Multi-framework IaC (Terraform + K8s + Docker) | **Checkov** | Widest platform coverage, 1000+ policies |
| Compliance-focused audit (PCI-DSS, HIPAA, SOC2) | **Terrascan** | Built-in compliance framework mapping via OPA |
| Pulumi YAML infrastructure | **KICS** | Only scanner with first-class Pulumi YAML support |
| Ansible playbooks | **KICS** | Only scanner with comprehensive Ansible query catalog |
| Unified multi-IaC pipeline | **KICS + Checkov** | KICS for Pulumi/Ansible, Checkov for Terraform/K8s |

---

### 3.5 CI/CD Integration Strategy

A practical multi-stage pipeline recommendation:

```
Stage 1 — Pre-commit (developer workstation)
  └── tfsec (fast, <5s, blocks commit on CRITICAL)

Stage 2 — Pull Request gate (CI)
  ├── Checkov (comprehensive Terraform + K8s scan)
  └── KICS (Pulumi YAML + Ansible scan)
  └── Fail PR if any CRITICAL or HIGH findings

Stage 3 — Scheduled audit (nightly)
  └── Terrascan (compliance-focused, OPA policies, full report)
  └── Store results in artifact store for audit trail
```

This layered approach keeps developer feedback loops fast while ensuring full coverage before merge and maintaining a compliance audit record.

---

### 3.6 Lessons Learned

**Tool effectiveness varies by category.** No single tool catches everything. tfsec found 9 CRITICAL network security issues that Terrascan missed entirely; Checkov found IAM issues that tfsec's severity model underweighted. Running two tools for Terraform (tfsec + Checkov) caught 53+78 = 131 total check failures vs. Terrascan's 22.

**KICS exit codes are non-zero by design.** When findings exist, KICS exits with a non-zero code. CI pipelines must use `|| true` or `--ignore-on-exit results` to distinguish "scan ran successfully but found issues" from "scan crashed."

**Pulumi Python SDK code is not scannable by KICS.** The `__main__.py` file containing 21 vulnerabilities was skipped — KICS only reads `Pulumi-vulnerable.yaml`. Projects using Pulumi Python, Go, or TypeScript need a different approach (e.g., custom OPA policies or Bridgecrew's Checkov support for Pulumi Python, which is still maturing).

**Ansible secrets scanning is a weak spot across the ecosystem.** Only KICS detected the hardcoded credentials in Ansible files. Teams relying solely on Terraform scanners for IaC security would miss the entire Ansible attack surface.

**False positive rate matters at scale.** tfsec's lower finding count (53 vs. Checkov's 78) partly reflects stricter default thresholds, not just narrower coverage. In a large codebase, Checkov's additional 25 findings would need triage time — a real operational cost.

---

## Scan Evidence

```
labs/lab6/analysis/
├── tfsec-results.json            (53 findings)
├── tfsec-report.txt
├── checkov-terraform-results.json (78 failed checks)
├── checkov-terraform-report.txt
├── terrascan-results.json        (22 violated policies)
├── terrascan-report.txt
├── kics-pulumi-results.json      (6 findings)
├── kics-pulumi-report.html
├── kics-pulumi-report.txt
├── kics-ansible-results.json     (10 findings)
├── kics-ansible-report.html
├── kics-ansible-report.txt
├── terraform-comparison.txt
├── pulumi-analysis.txt
├── ansible-analysis.txt
└── tool-comparison.txt
```
