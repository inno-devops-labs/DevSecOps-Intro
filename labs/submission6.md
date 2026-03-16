# Lab 6 - Infrastructure-as-Code Security: Scanning and Policy Enforcement

## Scope

- Analysis date: `2026-03-16`
- Target directories:
  - `labs/lab6/vulnerable-iac/terraform`
  - `labs/lab6/vulnerable-iac/pulumi`
  - `labs/lab6/vulnerable-iac/ansible`
- Tools used:
  - `aquasec/tfsec:latest`
  - `bridgecrew/checkov:latest`
  - `tenable/terrascan:latest`
  - `checkmarx/kics:latest`

## Commands Used

```bash
mkdir -p labs/lab6/analysis

# Terraform - tfsec
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src --format json > labs/lab6/analysis/tfsec-results.json
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src > labs/lab6/analysis/tfsec-report.txt

# Terraform - Checkov
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  bridgecrew/checkov:latest -d /tf --framework terraform -o json \
  > labs/lab6/analysis/checkov-terraform-results.json
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  bridgecrew/checkov:latest -d /tf --framework terraform --compact \
  > labs/lab6/analysis/checkov-terraform-report.txt

# Terraform - Terrascan
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac \
  tenable/terrascan:latest scan -i terraform -d /iac -o json \
  > labs/lab6/analysis/terrascan-results.json
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac \
  tenable/terrascan:latest scan -i terraform -d /iac -o human \
  > labs/lab6/analysis/terrascan-report.txt

# Pulumi (KICS)
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src \
  checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html
cp labs/lab6/vulnerable-iac/pulumi/kics-report/results.json \
  labs/lab6/analysis/kics-pulumi-results.json
cp labs/lab6/vulnerable-iac/pulumi/kics-report/results.html \
  labs/lab6/analysis/kics-pulumi-report.html
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src \
  checkmarx/kics:latest scan -p /src --minimal-ui \
  > labs/lab6/analysis/kics-pulumi-report.txt 2>&1

# Ansible (KICS)
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src \
  checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html
cp labs/lab6/vulnerable-iac/ansible/kics-report/results.json \
  labs/lab6/analysis/kics-ansible-results.json
cp labs/lab6/vulnerable-iac/ansible/kics-report/results.html \
  labs/lab6/analysis/kics-ansible-report.html
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src \
  checkmarx/kics:latest scan -p /src --minimal-ui \
  > labs/lab6/analysis/kics-ansible-report.txt 2>&1
```

Executed with Docker container commands from `labs/lab6.md`; generated artifacts are in `labs/lab6/analysis/`.

## Task 1 - Terraform and Pulumi Security Scanning

### Terraform tool comparison (tfsec vs Checkov vs Terrascan)

- tfsec findings: `53`
  - Critical: `9`, High: `25`, Medium: `11`, Low: `8`
  - Unique rules: `25`
- Checkov findings: `78` failed checks
  - Passed: `48`, Failed: `78`, Skipped: `0`
  - Unique checks: `45`
- Terrascan findings: `22` violated policies
  - High: `14`, Medium: `8`
  - Unique rules: `18`

Interpretation:
- Checkov had the widest Terraform policy coverage and the highest number of failed checks.
- tfsec produced stronger high-priority signal concentration (critical/high findings on SG, IAM, and public data exposure).
- Terrascan produced lower volume but focused policy/compliance-oriented violations.

### Pulumi security analysis (KICS)

- KICS Pulumi findings: `6`
  - Critical: `1`, High: `2`, Medium: `1`, Info: `2`
- Files scanned: `1` (`Pulumi-vulnerable.yaml`)
- Queries executed: `21`

Detected Pulumi issues included:
- `RDS DB Instance Publicly Accessible` (CRITICAL)
- `DynamoDB Table Not Encrypted` (HIGH)
- `Passwords And Secrets - Generic Password` (HIGH)
- `EC2 Instance Monitoring Disabled` (MEDIUM)

### Terraform vs Pulumi (HCL vs Pulumi YAML)

- Common issue classes in both:
  - Public exposure (`0.0.0.0/0`, public RDS)
  - Missing encryption (S3/RDS/DynamoDB)
  - Overly permissive IAM
  - Hardcoded secrets
- Terraform scan output was richer across three engines; Pulumi was scanned with KICS only, so findings are lower-volume but still high-impact.
- Pulumi YAML scanning worked well for structural misconfigs, but Python Pulumi (`__main__.py`) was not scanned by KICS in this run.

### KICS Pulumi support evaluation

- Strengths observed:
  - Correct platform detection (`Pulumi`)
  - Good query metadata (CWE, risk score, category, expected vs actual values)
  - Useful HTML report for triage
- Limitation observed:
  - This run covered Pulumi YAML only (`files_scanned: 1`) and did not evaluate Python Pulumi source.

### Critical findings (at least 5)

1. Hardcoded AWS credentials in Terraform provider (`main.tf:8-9`).
2. Public S3 bucket ACL (`main.tf:15`).
3. Security groups open to internet on SSH/RDP/DB and all protocols (`security_groups.tf:15`, `41`, `49`, `75`, `83`).
4. Unencrypted + publicly accessible RDS (`database.tf:15`, `17`).
5. IAM wildcard permissions (`iam.tf:10`, `72`).
6. Pulumi RDS publicly accessible (`Pulumi-vulnerable.yaml:104`).

### Tool strengths summary

- tfsec: fast, Terraform-specific, clear high/critical misconfiguration signal.
- Checkov: strongest breadth and policy catalog (especially IAM/compliance controls).
- Terrascan: concise policy/compliance perspective, useful second-opinion scanner.
- KICS: strong multi-framework support (Pulumi YAML + Ansible) and effective secrets detection.

## Task 2 - Ansible Security Scanning with KICS

### Ansible security issues detected

- KICS Ansible findings: `10`
  - High: `9`, Low: `1`
- Query occurrence breakdown:
  - `Passwords And Secrets - Generic Password`: `6`
  - `Passwords And Secrets - Generic Secret`: `1`
  - `Passwords And Secrets - Password in URL`: `2`
  - `Unpinned Package Version`: `1`

Most significant detected issues:
- Plaintext passwords/secrets in `inventory.ini` (`lines 5, 10, 18, 19, 20`).
- Hardcoded secrets in playbooks (`deploy.yml:12`, `14`; `configure.yml:16`).
- Password in repository URL (`deploy.yml:72`).

### Best-practice violations and impact (3+)

1. Hardcoded credentials in inventory/playbooks.
   - Impact: immediate credential leakage and lateral movement risk.
2. Password embedded in URL.
   - Impact: secret exposure in logs/process lists/proxies.
3. Unpinned package version (`state: latest`).
   - Impact: non-deterministic deployments and supply-chain drift.

### KICS Ansible query coverage evaluation

- Strong at secrets hygiene and credential leakage detection.
- Detected multiple hardcoded secret patterns across `.ini` and `.yml` files.
- Lower coverage in this run for network hardening and privilege-escalation logic compared to dedicated Ansible linters and policy engines.

### Remediation steps

- Move all secrets to Ansible Vault or external secret manager.
- Add `no_log: true` for tasks handling credentials.
- Remove credentials from URLs; use deploy tokens or SSH keys.
- Pin package versions instead of `latest`.
- Enforce secure inventory practices and separate prod credentials from dev.

## Task 3 - Comparative Tool Analysis and Security Insights

### Tool comparison matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|---|---|---|---|---|
| **Total Findings** | 53 | 78 | 22 | 16 (Pulumi 6 + Ansible 10) |
| **Scan Speed** | Fast (`~2.93s`) | Medium (`~12.38s`) | Slow/Medium (`~15.75s`) | Medium (`~3.00s` Pulumi, `~8.82s` Ansible) |
| **False Positives** | Low | Medium | Low/Medium | Medium |
| **Report Quality** | 4/5 | 4/5 | 3/5 | 4/5 |
| **Ease of Use** | Easy | Easy/Medium | Medium | Medium |
| **Documentation** | 4/5 | 5/5 | 4/5 | 4/5 |
| **Platform Support** | Terraform-focused | Multi-framework | Multi-framework | Multi-framework |
| **Output Formats** | JSON, text, SARIF | JSON, CLI, SARIF, CycloneDX | JSON, human, YAML, XML | JSON, HTML, SARIF |
| **CI/CD Integration** | Easy | Easy | Medium | Medium |
| **Unique Strengths** | Fast Terraform misconfig checks | Broad policy depth (IAM/compliance) | Policy/compliance perspective | Unified Pulumi/Ansible + secrets detection |

### Vulnerability category analysis

Counts are normalized from scanner outputs by issue keywords/categories.

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|---|---:|---:|---:|---:|---:|---|
| **Encryption Issues** | 7 | 4 | 2 | 1 | 0 | tfsec |
| **Network Security** | 17 | 17 | 7 | 1 | 0 | tfsec / Checkov |
| **Secrets Management** | 0 | 3 | 0 | 1 | 9 | KICS |
| **IAM/Permissions** | 11 | 25 | 3 | 0 | 0 | Checkov |
| **Access Control** | 5 | 3 | 1 | 0 | 0 | tfsec |
| **Compliance/Best Practices** | 13 | 26 | 9 | 3 | 1 | Checkov |

### Top 5 critical findings with remediation examples

1. Terraform hardcoded AWS credentials (`main.tf:8-9`)

```hcl
# bad
access_key = "AKIA..."
secret_key = "..."

# good
# Use environment variables/AWS profile; do not set static keys in code.
```

2. Terraform public-open security groups (`security_groups.tf:15`, `41`, `49`, `75`, `83`)

```hcl
# bad
cidr_blocks = ["0.0.0.0/0"]

# good
cidr_blocks = [var.allowed_admin_cidr]
```

3. Terraform RDS public and unencrypted (`database.tf:15`, `17`)

```hcl
# bad
storage_encrypted   = false
publicly_accessible = true

# good
storage_encrypted   = true
publicly_accessible = false
backup_retention_period = 7
deletion_protection = true
```

4. IAM wildcard permissions (`iam.tf:10`, `72`)

```hcl
# bad
Action   = "*"
Resource = "*"

# good
Action   = ["s3:GetObject", "s3:PutObject"]
Resource = ["arn:aws:s3:::my-bucket/*"]
```

5. Ansible plaintext credentials + password in URL (`inventory.ini:5`, `10`, `18`, `19`, `20`; `deploy.yml:72`)

```yaml
# bad
repo: "https://username:password@github.com/company/repo.git"

# good
repo: "git@github.com:company/repo.git"
no_log: true
```

### Tool selection guide

- Use `tfsec` for fast Terraform gate checks in PR pipelines.
- Use `Checkov` for broad policy-as-code coverage and IAM/compliance depth.
- Use `Terrascan` as a second-opinion policy/compliance scanner.
- Use `KICS` for Pulumi YAML and Ansible, especially to catch secret leakage patterns.

### Lessons learned

- No single tool gave full coverage across all IaC frameworks and issue domains.
- Checkov and tfsec overlap on Terraform but provide complementary strengths (breadth vs focused signal).
- KICS is effective for Pulumi YAML and Ansible secret hygiene, but language coverage matters (YAML vs Python).
- Multi-tool pipelines are necessary to reduce blind spots.

### CI/CD integration strategy

1. Pre-commit: tfsec (Terraform), KICS quick scan (Pulumi/Ansible) with developer feedback.
2. PR pipeline: Checkov + tfsec for Terraform, KICS for Pulumi/Ansible; fail on CRITICAL/HIGH.
3. Nightly/compliance: Terrascan full policy run and trend reporting.
4. Release gate: enforce zero CRITICAL, approved exceptions only, and tracked remediation SLAs.

### Justification for tool choices

- The selected stack balances speed (`tfsec`), policy breadth (`Checkov`), compliance signal (`Terrascan`), and cross-framework support (`KICS`).
- Empirical run data from this lab supports this composition:
  - Highest Terraform coverage from Checkov.
  - Best high-priority Terraform signal density from tfsec.
  - Best secret-leakage detection in Ansible/Pulumi YAML from KICS.

## Generated Artifacts

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

## Issues encountered

- Docker daemon was initially unavailable and required elevated Docker access before scans could run.
