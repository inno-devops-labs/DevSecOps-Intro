# Lab 6 Submission — Infrastructure-as-Code Security: Scanning & Comparative Analysis

## Student / Context
- Name: `Danil Fishchenko`
- Branch: `feature/lab6`
- Scan date: `2026-03-16`
- Host OS: `macOS`
- Command execution directory: repository root `DevSecOps-Intro/`
- Scanned source directory: `labs/lab6/vulnerable-iac/`
- Tools used:
  - `aquasec/tfsec:latest`
  - `bridgecrew/checkov:latest`
  - `tenable/terrascan:latest`
  - `checkmarx/kics:latest`

## Scope And Method
This lab is based on the intentionally vulnerable IaC sample under `labs/lab6/vulnerable-iac/`. I did not modify the vulnerable source. The work consisted of:

1. Scanning Terraform with `tfsec`, `Checkov`, and `Terrascan`.
2. Scanning Pulumi YAML and Ansible with `KICS`.
3. Manually reviewing the vulnerable source to validate findings, identify blind spots, and produce remediation guidance.

Important note on result interpretation:
- Raw finding counts are not directly equal to the number of source vulnerabilities.
- Some tools emit multiple findings for one insecure resource.
- Some tools miss vulnerabilities that are clearly present in the source.

## Task 1 — Terraform And Pulumi Security Scanning

### 1.1 Environment Setup
```bash
mkdir -p labs/lab6/analysis
```

### 1.2 Commands Used
```bash
PULUMI_KICS_OUT="$(mktemp -d /tmp/lab6-kics-pulumi.XXXXXX)"

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src \
  --format json > labs/lab6/analysis/tfsec-results.json

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src > labs/lab6/analysis/tfsec-report.txt

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  bridgecrew/checkov:latest \
  -d /tf --framework terraform \
  -o json > labs/lab6/analysis/checkov-terraform-results.json

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  bridgecrew/checkov:latest \
  -d /tf --framework terraform \
  --compact > labs/lab6/analysis/checkov-terraform-report.txt

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac \
  tenable/terrascan:latest scan \
  -i terraform -d /iac \
  -o json > labs/lab6/analysis/terrascan-results.json

docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac \
  tenable/terrascan:latest scan \
  -i terraform -d /iac \
  -o human > labs/lab6/analysis/terrascan-report.txt

docker run --rm --user "$(id -u):$(id -g)" \
  -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src \
  -v "${PULUMI_KICS_OUT}":/out \
  checkmarx/kics:latest \
  scan -p /src -o /out --report-formats json,html

mv "${PULUMI_KICS_OUT}/results.json" \
  labs/lab6/analysis/kics-pulumi-results.json
mv "${PULUMI_KICS_OUT}/results.html" \
  labs/lab6/analysis/kics-pulumi-report.html
rm -rf "${PULUMI_KICS_OUT}"

docker run --rm --user "$(id -u):$(id -g)" \
  -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src \
  checkmarx/kics:latest \
  scan -p /src --minimal-ui --ignore-on-exit results \
  > labs/lab6/analysis/kics-pulumi-report.txt 2>&1
```

### 1.3 Terraform Tool Comparison

| Tool | Findings | Severity / Summary | Approx. Speed | Main Strength |
|---|---:|---|---|---|
| `tfsec` | `53` | `CRITICAL=9, HIGH=25, MEDIUM=11, LOW=8` | Fast | Fast, Terraform-specific signal with strong cloud misconfiguration coverage |
| `Checkov` | `78` | `failed=78, passed=48` | Slowest in this lab | Broadest Terraform policy coverage, especially IAM and governance checks |
| `Terrascan` | `22` | `HIGH=14, MEDIUM=8` | Medium | Compact compliance-style results and clear policy taxonomy |

#### tfsec
`tfsec` produced the best fast-feedback experience. It strongly highlighted the highest-risk Terraform issues:
- open ingress and egress in security groups;
- public S3 and missing S3 public access controls;
- unencrypted/public RDS instances;
- permissive IAM documents.

Representative findings:
- `AVD-AWS-0107` ingress from `/0`
- `AVD-AWS-0104` egress to `/0`
- `AVD-AWS-0088` unencrypted S3 bucket
- `AVD-AWS-0180` RDS publicly accessible
- `AVD-AWS-0057` wildcard IAM permissions

Evidence excerpt from `tfsec-results.json`:
```text
AVD-AWS-0180  RDS Publicly Accessible  aws_db_instance.unencrypted_db.publicly_accessible
AVD-AWS-0107  An ingress security group rule allows traffic from /0.  aws_security_group.database_exposed
```

#### Checkov
`Checkov` found the highest number of Terraform issues and had the best breadth. It surfaced not only core exposure problems but also governance and operational hardening gaps:
- `performance insights` disabled;
- `enhanced monitoring` disabled;
- `IAM authentication` disabled for RDS;
- S3 logging, lifecycle, event notifications, replication, and KMS usage gaps;
- many IAM policy abuse patterns and privilege-escalation style checks.

Representative findings:
- `CKV_AWS_41` hardcoded AWS credentials in provider
- `CKV_AWS_286` IAM privilege escalation risk
- `CKV_AWS_273` IAM user instead of SSO
- `CKV_AWS_145` S3 bucket not encrypted with KMS
- `CKV2_AWS_60` RDS copy-tags-to-snapshots disabled

Evidence excerpt from `checkov-terraform-results.json`:
```text
CKV_AWS_41   Ensure no hard coded AWS access key and secret key exists in provider   aws.default
CKV_AWS_286  Ensure IAM policies does not allow privilege escalation                  aws_iam_policy.admin_policy
```

Limitation:
- In this run, the JSON output did not include severity values, so prioritization had to rely on rule meaning rather than an explicit severity field.

#### Terrascan
`Terrascan` returned fewer findings than `tfsec` and `Checkov`, but they were high-signal and clearly mapped to compliance-style concerns:
- exposed SSH/RDP/MySQL/PostgreSQL ports;
- public S3;
- unencrypted DynamoDB and RDS;
- missing backups and CloudWatch logs;
- exposed IAM access keys.

Representative findings:
- `AC_AWS_0275` security group open to all traffic
- `AC_AWS_0227` unrestricted SSH
- `AC_AWS_0054` RDS publicly accessible
- `AC_AWS_0058` unencrypted RDS storage
- `AC_AWS_0133` IAM access key exposure

Evidence excerpt from `terrascan-results.json`:
```text
AC_AWS_0054  RDS Instance publicly_accessible flag is true                                          unencrypted_db
AC_AWS_0275  Ensure no security groups is wide open to public, that is, allows traffic from 0.0.0.0/0 to ALL ports and protocols  allow_all
```

### 1.4 Terraform Tool Effectiveness
My conclusion for Terraform is:
- `Checkov` is the best broad CI gate when the goal is maximum policy coverage.
- `tfsec` is the best fast PR feedback tool because it is quick and focused.
- `Terrascan` is useful as a secondary compliance-oriented lens, but not sufficient alone on this codebase.

### 1.5 Pulumi Security Analysis With KICS

Pulumi scan summary:
- Total findings: `6`
- Severity: `CRITICAL=1`, `HIGH=2`, `MEDIUM=1`, `INFO=2`
- Queries evaluated: `21`

Detected findings:
- `RDS DB Instance Publicly Accessible`
- `DynamoDB Table Not Encrypted`
- `Passwords And Secrets - Generic Password`
- `EC2 Instance Monitoring Disabled`
- `DynamoDB Table Point In Time Recovery Disabled`
- `EC2 Not EBS Optimized`

Evidence excerpt from `kics-pulumi-results.json`:
```text
RDS DB Instance Publicly Accessible  CRITICAL  ../../src/Pulumi-vulnerable.yaml:104
```

Representative evidence from the Pulumi YAML:
- hardcoded secrets in variables at `Pulumi-vulnerable.yaml`
- public RDS at `publiclyAccessible: true`
- unencrypted DynamoDB and disabled PITR
- EC2 instance configuration issues

### 1.6 Terraform vs Pulumi
At the vulnerability-class level, Terraform and Pulumi are very similar in this lab:
- both expose public attack surface through permissive security groups and public-facing database access;
- both contain storage and database encryption gaps;
- both contain overly permissive IAM patterns;
- both embed secrets directly in IaC rather than loading them from protected secret sources.

The main difference is where the risk is expressed:
- Terraform concentrates risk in declarative cloud resources and variable defaults, such as public access enabled by default, encryption disabled by default, broad security groups, and IAM access key exposure through outputs.
- Pulumi adds programmatic secret-handling risk on top of similar cloud misconfigurations, including secrets in `userData`, secrets exported through outputs, default secrets in `Pulumi.yaml`, and hardcoded credentials in Python code.

Pulumi also contains a few problem classes that are less prominent in the Terraform sample:
- EKS control-plane exposure via public endpoint access;
- EBS volume encryption gaps;
- CloudWatch log-group retention and KMS gaps;
- EC2 operational hardening issues such as monitoring disabled.

Terraform, by contrast, is stronger in the sample on governance-style misconfiguration patterns:
- insecure variable defaults driving public access and disabled encryption;
- explicit `aws_s3_bucket_public_access_block` misconfiguration;
- IAM access keys created for a service account and exposed through outputs.

Scanner coverage was also asymmetric:
- Terraform was checked by three specialized tools and produced rich, overlapping evidence.
- Pulumi was only scanned by `KICS`, and in this run `KICS` reported findings only against the YAML manifest rather than against the Python source or Pulumi config.

So the correct conclusion is not “Pulumi is safer”; the correct conclusion is that the two stacks share similar core cloud risks, while Pulumi adds extra secret-handling and programmatic-IaC exposure patterns that this scan setup only partially covered.

### 1.7 KICS Pulumi Support Evaluation
`KICS` did prove that Pulumi YAML is supported, and it did catch real YAML-level infrastructure risks. However, coverage was limited in practice:
- it worked well for straightforward resource misconfigurations;
- it under-reported the full attack surface of the mixed Pulumi stack;
- it did not provide the same breadth as the Terraform toolset;
- it should be paired with manual review or language-aware SAST for Pulumi Python.

## Task 2 — Ansible Security Scanning With KICS

### 2.1 Commands Used
```bash
ANSIBLE_KICS_OUT="$(mktemp -d /tmp/lab6-kics-ansible.XXXXXX)"

docker run --rm --user "$(id -u):$(id -g)" \
  -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src \
  -v "${ANSIBLE_KICS_OUT}":/out \
  checkmarx/kics:latest \
  scan -p /src -o /out --report-formats json,html

mv "${ANSIBLE_KICS_OUT}/results.json" \
  labs/lab6/analysis/kics-ansible-results.json
mv "${ANSIBLE_KICS_OUT}/results.html" \
  labs/lab6/analysis/kics-ansible-report.html
rm -rf "${ANSIBLE_KICS_OUT}"

docker run --rm --user "$(id -u):$(id -g)" \
  -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src \
  checkmarx/kics:latest \
  scan -p /src --minimal-ui --ignore-on-exit results \
  > labs/lab6/analysis/kics-ansible-report.txt 2>&1
```

### 2.2 KICS Ansible Results
- Total findings: `10`
- Severity: `HIGH=9`, `LOW=1`
- Queries evaluated: `287`

Findings actually reported by `KICS`:
- plaintext passwords in `deploy.yml`, `configure.yml`, and `inventory.ini`;
- secrets in inventory variables;
- credentials embedded in `db_connection` and in the Git repository URL;
- unpinned package version via `state: latest`.

Representative KICS findings:
- `Passwords And Secrets - Generic Password`
- `Passwords And Secrets - Generic Secret`
- `Passwords And Secrets - Password in URL`
- `Unpinned Package Version`

Evidence excerpt from `kics-ansible-results.json`:
```text
Passwords And Secrets - Password in URL  HIGH  ../../src/deploy.yml:16
Passwords And Secrets - Password in URL  HIGH  ../../src/deploy.yml:72
```

### 2.3 Key Ansible Security Issues
The Ansible code contains many high-risk issues beyond the 10 findings reported by KICS:

- Hardcoded secrets in playbook vars and inventory.
- Secrets written to files and logs without `no_log: true`.
- Dangerous `shell` and `raw` use for package installation, command execution, and firewall flushing.
- SSH hardening disabled: root login, password auth, and empty passwords allowed.
- Passwordless sudo for all commands.
- Firewall and SELinux protections disabled.
- Insecure inventory model with root credentials in plaintext.

### 2.4 Best Practice Violations
At least three major violations and their impact:

1. Secrets in plaintext inventory and playbooks
   - Impact: anyone with repo access or CI log access can recover credentials immediately.
   - Evidence: `inventory.ini`, `deploy.yml`, `configure.yml`.

2. Missing `no_log: true` on secret-bearing tasks
   - Impact: sensitive values may leak into Ansible stdout, CI logs, and audit systems.
   - Evidence: MySQL password command, debug output, environment writes.

3. Using `shell`/`raw` instead of safer modules
   - Impact: command injection, poor idempotence, harder auditing, and weaker linting.
   - Evidence: `curl http://example.com/setup.sh | bash`, `rm -rf {{ user_input }}/*`, `raw: iptables -F`.

Additional violations:
- weak SSH configuration;
- passwordless sudo;
- disabled host protection layers;
- downloading over HTTP without checksum validation;
- non-deterministic package installation using `latest`.

### 2.5 KICS Ansible Query Evaluation
`KICS` was strongest on secret discovery. That is useful, but insufficient:
- true positives were strong and easy to validate;
- false positives were low on this repository;
- false negatives were significant, because many obvious misconfigurations were not detected.

The practical lesson is that `KICS` is a baseline Ansible scanner, not a complete hardening audit.

### 2.6 Remediation Steps
- Move secrets to `Ansible Vault` or an external secret manager.
- Add `no_log: true` to every task that handles passwords, tokens, keys, or connection strings.
- Replace `shell` and `raw` with dedicated modules such as `apt`, `file`, `service`, `ufw`, `git`, and `template`.
- Remove root login and password authentication from SSH.
- Remove `NOPASSWD: ALL` and reduce privilege escalation to the minimum necessary.
- Stop storing inventory passwords in plaintext.
- Pin package versions and verify downloaded artifacts by checksum and HTTPS.

## Task 3 — Comparative Tool Analysis And Security Insights

### 3.1 Tool Comparison Matrix

Only `Total Findings`, `Platform Support In Practice Here`, and `Output Formats Used In This Lab` are direct artifact-backed fields. The remaining rows are qualitative operator assessment based on local execution experience, manual validation against source, and report usability.

| Criterion | tfsec | Checkov | Terrascan | KICS |
|---|---|---|---|---|
| Total Findings | `53` | `78` | `22` | `16` total (`6` Pulumi + `10` Ansible) |
| Scan Speed (qualitative) | Fast | Slowest in this lab | Medium | Medium |
| False Positives (qualitative) | Low | Low to Medium | Low | Low |
| Report Quality (qualitative) | `4/5` | `4/5` | `3/5` | `4/5` |
| Ease of Use (qualitative) | `5/5` | `4/5` | `3/5` | `4/5` |
| Documentation / Discoverability (qualitative) | `4/5` | `4/5` | `3/5` | `4/5` |
| Platform Support In Practice Here | Terraform only | Multiple IaC frameworks, used here for Terraform | Multiple IaC frameworks, used here for Terraform | Multiple IaC frameworks, used here for Pulumi and Ansible |
| Output Formats Used In This Lab | JSON, text | JSON, compact text | JSON, human text | JSON, HTML, console text |
| CI/CD Integration (qualitative) | Easy | Easy to Medium | Medium | Easy |
| Unique Strengths | Fast Terraform-first feedback | Broad policy catalog and best-practice depth | Compact compliance-oriented policy view | One scanner across Pulumi YAML and Ansible |

### 3.2 Category Analysis
The table below uses a normalized primary-category mapping over rule names and descriptions. I assigned each finding to one dominant category using the first matching rule below. This is still an approximation, but it is explicit and defendable:

- `Encryption Issues`: any rule mentioning `encrypt`, `encryption`, `KMS`, `CMK`, `SSE`, or at-rest protection.
- `Network Security`: security groups, ingress/egress, exposed ports, public interfaces, public endpoints.
- `Secrets Management`: hardcoded passwords, secrets, tokens, API keys, credentials in URLs, sensitive output leakage.
- `IAM / Permissions`: IAM policies, roles, users, access keys, wildcard permissions, privilege escalation.
- `Access Control`: public ACL/public-read/public access block problems, root authentication, insecure SSH access controls.
- `Compliance / Best Practices`: logging, monitoring, backups, PITR, lifecycle, version pinning, retention, Multi-AZ, replication, general hardening.

Notes:
- I normalized vendor-specific rule taxonomies into the six course categories above.
- Each finding was counted once in its primary category; I did not multi-count one rule across several categories.
- For `KICS`, I counted file-level hits from each query, not just the number of unique query names. This matters most for Ansible, where one secret-detection query matched multiple files and lines.
- The table includes only scanner-reported findings. Manual-review-only issues were analyzed separately and were not mixed into these counts.

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|---|---:|---:|---:|---:|---:|---|
| Encryption Issues | `7` | `4` | `2` | `1` | `0` | `tfsec` |
| Network Security | `14` | `15` | `5` | `1` | `0` | `Checkov` |
| Secrets Management | `0` | `3` | `0` | `1` | `9` | `KICS` for secret leakage, `Checkov` for Terraform creds |
| IAM / Permissions | `14` | `25` | `4` | `0` | `0` | `Checkov` |
| Access Control | `6` | `5` | `1` | `0` | `0` | `tfsec` |
| Compliance / Best Practices | `12` | `26` | `10` | `3` | `1` | `Checkov` |

Key interpretation:
- `Checkov` dominated IAM and operational best-practice checks.
- `tfsec` was strongest on the most dangerous Terraform exposure patterns.
- `Terrascan` found fewer issues but gave a useful compliance-oriented subset.
- `KICS` was most valuable for obvious secret leakage, especially in Ansible, where `9` of `10` findings were credential-related.

### 3.2.1 Unique Findings By Tool
The assignment asks for unique detections, so the most important tool-specific examples in this lab were:

- `tfsec`
  - `AVD-AWS-0104` public egress from security groups.
  - `AVD-AWS-0091` / `AVD-AWS-0093` S3 access-block specifics such as ignoring public ACLs and restricting public buckets.

- `Checkov`
  - `CKV_AWS_41` hardcoded AWS access key and secret in provider configuration.
  - `CKV_AWS_273` guidance to prefer SSO over IAM users.
  - `CKV2_AWS_60` copy-tags-to-snapshots on RDS.
  - multiple S3 governance checks such as lifecycle, event notifications, replication, and logging depth.

- `Terrascan`
  - `AC_AWS_0133` exposed IAM access key creation.
  - `AC_AWS_0454` missing CloudWatch logging for RDS.
  - concise port-specific network findings such as `AC_AWS_0227` for SSH and `AC_AWS_0262` for PostgreSQL exposure.

- `KICS (Pulumi)`
  - Pulumi-YAML-specific result for `RDS DB Instance Publicly Accessible` at `Pulumi-vulnerable.yaml:104`.
  - direct YAML secret detection for `dbPassword` in `Pulumi-vulnerable.yaml:16`.

- `KICS (Ansible)`
  - `Passwords And Secrets - Password in URL` matched both `deploy.yml:16` (`db_connection`) and `deploy.yml:72` (Git repo URL).
  - `Unpinned Package Version` matched `deploy.yml:99`, which none of the Terraform scanners would ever surface.

### 3.3 Top 5 Critical Findings

The critical findings below are grounded in the raw scanner excerpts quoted in Sections `1.3`, `1.5`, and `2.2`, and then cross-checked against the vulnerable source files.

#### 1. Hardcoded secrets and credentials in IaC
Evidence:
- Terraform provider hardcodes AWS keys.
- Pulumi Python hardcodes AWS keys, DB password, and API key.
- Pulumi config defaults include secrets.
- Ansible playbooks and inventory contain passwords in plaintext.

Why it matters:
- immediate credential compromise;
- secrets leak into VCS history, CI logs, and state/output systems;
- easy lateral movement after repo disclosure.

Remediation example:
```hcl
variable "db_password" {
  type      = string
  sensitive = true
}
```

```python
config = pulumi.Config()
db_password = config.require_secret("db_password")
api_key = config.require_secret("api_key")
```

```yaml
- name: Load DB password from vault
  set_fact:
    db_password: "{{ vault_db_password }}"
  no_log: true
```

#### 2. Security groups and public endpoints open to the internet
Evidence:
- Terraform security groups allow `0.0.0.0/0` for all traffic, SSH, RDP, MySQL, and PostgreSQL.
- Pulumi YAML exposes SSH/RDP and public RDS.
- Pulumi EKS endpoint allows `0.0.0.0/0`.

Why it matters:
- direct remote attack surface;
- brute force, credential stuffing, RCE, and database exposure risk;
- unnecessary internet reachability for administrative services.

Remediation example:
```hcl
ingress {
  description = "SSH only from corp VPN"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["203.0.113.0/24"]
}
```

#### 3. Public and unencrypted data stores
Evidence:
- public S3 bucket with `acl = "public-read"`;
- missing S3 encryption and public access block;
- unencrypted/public RDS instance;
- DynamoDB tables without encryption and PITR.

Why it matters:
- confidentiality failure;
- backup and recovery weakness;
- data loss or tampering risk.

Remediation example:
```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_sse" {
  bucket = aws_s3_bucket.secure_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
```

```hcl
resource "aws_db_instance" "secure_db" {
  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 7
  deletion_protection     = true
}
```

#### 4. Overly permissive IAM and privilege escalation paths
Evidence:
- Terraform IAM policy with `Action = "*"` and `Resource = "*"`;
- inline IAM user policy with broad `ec2:*`, `s3:*`, `rds:*`;
- access key created for service account;
- explicit privilege escalation actions like `iam:CreatePolicy` and `iam:AttachUserPolicy`;
- Pulumi YAML mirrors the same wildcard IAM pattern.

Why it matters:
- least privilege is completely broken;
- trivial pivot from one compromised principal to account-wide control;
- easier persistence and data exfiltration.

Remediation example:
```hcl
policy = jsonencode({
  Version = "2012-10-17"
  Statement = [{
    Effect   = "Allow"
    Action   = ["s3:GetObject"]
    Resource = ["arn:aws:s3:::my-app-bucket/*"]
  }]
})
```

#### 5. Insecure Ansible automation patterns
Evidence:
- `shell: curl http://example.com/setup.sh | bash`
- `raw: iptables -F`
- missing `no_log` on secret-bearing tasks
- root SSH and password auth enabled
- `NOPASSWD: ALL`

Why it matters:
- command injection and arbitrary code execution;
- operational drift and weak auditability;
- secret leakage into logs and terminals;
- lower barrier for privilege escalation.

Remediation example:
```yaml
- name: Install packages safely
  apt:
    name:
      - nginx=1.24.0-1
      - mysql-client=8.0.39-1
    state: present
    update_cache: true

- name: Create database without leaking password
  community.mysql.mysql_db:
    name: myapp
    state: present
    login_user: root
    login_password: "{{ vault_db_password }}"
  no_log: true
```

### 3.4 Tool Selection Guide
- Use `tfsec` in pull requests for fast Terraform-first feedback.
- Use `Checkov` as the main merge gate because it provides the broadest policy catalog and the strongest IAM/governance signal.
- Use `Terrascan` as a secondary compliance-oriented scanner, especially when a concise, policy-ID-driven report is useful.
- Use `KICS` for Pulumi YAML and Ansible as a baseline scanner, but do not treat it as complete coverage.
- Add manual review or language-aware SAST for Pulumi Python and stricter lint/policy checks for Ansible.

### 3.5 Lessons Learned
- The biggest difference between tools was not only the finding count, but what they considered “in scope”.
- Terraform-native tooling is much more mature than Pulumi/Ansible coverage in this lab setup.
- `KICS` had strong secret detection but notable blind spots in operational hardening and IaC logic.
- `Checkov` was the best single Terraform gate for broad security and governance coverage.
- `tfsec` is the best fast-feedback scanner for obvious Terraform risk patterns.
- Scanner output must always be validated against the source because false negatives matter just as much as false positives.

### 3.6 CI/CD Integration Strategy
Recommended multi-stage pipeline:

1. Pre-commit / developer workstation
   - `tfsec` on Terraform diffs
   - secret scanning on the repository

2. Pull request gate
   - `Checkov` on Terraform
   - `KICS` on Pulumi YAML and Ansible

3. Merge / nightly compliance stage
   - `Terrascan` for policy-oriented reporting
   - custom `OPA/Conftest` rules for organization-specific standards

4. Manual review requirements
   - Pulumi Python logic
   - Ansible `shell`, `raw`, `no_log`, SSH hardening, and privilege escalation patterns

### 3.7 Justification
My recommended combination is:
- `tfsec` + `Checkov` for Terraform;
- `KICS` for Pulumi YAML and Ansible;
- optional `Terrascan` for compliance-style reporting;
- manual review or custom policy enforcement for the gaps that open-source scanning did not cover.

This recommendation is justified by the actual local results:
- `Checkov` found the broadest Terraform issue set.
- `tfsec` surfaced the most dangerous Terraform exposures very quickly.
- `Terrascan` had useful but narrower Terraform coverage.
- `KICS` worked, but coverage for Pulumi Python and many Ansible hardening issues was incomplete.

## Challenges Encountered
- `tfsec`, `Checkov`, and `KICS` exit non-zero when findings exist; this is expected and not a scan failure.
- In the documented `KICS` commands I used `--ignore-on-exit results` so the commands remain copy-paste-safe under `set -e` while still preserving finding output.
- `Checkov` JSON did not provide severity values in this run, so severity-based prioritization had to be inferred from rule semantics.
- `KICS` console output was post-processed before commit to remove ANSI escape sequences and progress-bar noise from the text artifacts.

## Evidence Files
- `labs/lab6/analysis/tfsec-results.json`
- `labs/lab6/analysis/tfsec-report.txt`
- `labs/lab6/analysis/checkov-terraform-results.json`
- `labs/lab6/analysis/checkov-terraform-report.txt`
- `labs/lab6/analysis/terrascan-results.json`
- `labs/lab6/analysis/terrascan-report.txt`
- `labs/lab6/analysis/kics-pulumi-results.json`
- `labs/lab6/analysis/kics-pulumi-report.html`
- `labs/lab6/analysis/kics-pulumi-report.txt`
- `labs/lab6/analysis/kics-ansible-results.json`
- `labs/lab6/analysis/kics-ansible-report.html`
- `labs/lab6/analysis/kics-ansible-report.txt`
- `labs/lab6/analysis/terraform-comparison.txt`
- `labs/lab6/analysis/pulumi-analysis.txt`
- `labs/lab6/analysis/ansible-analysis.txt`
- `labs/lab6/analysis/tool-comparison.txt`
