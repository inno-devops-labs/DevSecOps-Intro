# Lab 6 - IaC Security Scanning and Policy Analysis

## Scope
- Target code:
  - Terraform: `labs/lab6/vulnerable-iac/terraform/`
  - Pulumi: `labs/lab6/vulnerable-iac/pulumi/`
  - Ansible: `labs/lab6/vulnerable-iac/ansible/`
- Tools used:
  - Terraform: `tfsec`, `Checkov`, `Terrascan`
  - Pulumi + Ansible: `KICS`

## Task 1 - Terraform & Pulumi Security Scanning

### Generated Artifacts
- Terraform:
  - `labs/lab6/analysis/tfsec-results.json`
  - `labs/lab6/analysis/tfsec-report.txt`
  - `labs/lab6/analysis/checkov-terraform-results.json`
  - `labs/lab6/analysis/checkov-terraform-report.txt`
  - `labs/lab6/analysis/terrascan-results.json`
  - `labs/lab6/analysis/terrascan-report.txt`
  - `labs/lab6/analysis/terraform-comparison.txt`
- Pulumi (KICS):
  - `labs/lab6/analysis/kics-pulumi-results.json`
  - `labs/lab6/analysis/kics-pulumi-report.html`
  - `labs/lab6/analysis/kics-pulumi-report.txt`
  - `labs/lab6/analysis/pulumi-analysis.txt`

### Terraform Tool Comparison
| Tool | Findings |
|---|---:|
| tfsec | 53 |
| Checkov | 78 |
| Terrascan | 22 |

Notes:
- tfsec provided strong severity labeling: `CRITICAL 9`, `HIGH 25`, `MEDIUM 11`, `LOW 8`.
- Checkov found the highest volume (`78`) and strongest breadth of policy checks (IAM/compliance-heavy).
- Terrascan produced fewer findings (`22`) but high signal in network/data-protection/compliance categories.

### Pulumi Security Analysis (KICS)
- Total findings: `6`
- Severity:
  - CRITICAL: `1`
  - HIGH: `2`
  - MEDIUM: `1`
  - INFO: `2`

Key Pulumi findings:
- `RDS DB Instance Publicly Accessible` (CRITICAL)
- `DynamoDB Table Not Encrypted` (HIGH)
- `Passwords And Secrets - Generic Password` (HIGH)
- `EC2 Instance Monitoring Disabled` (MEDIUM)

### Terraform vs Pulumi (Observed)
- Terraform scan volume is much higher (`53-78` findings across tools) due broader policy catalogs and multiple scanner overlap.
- Pulumi KICS findings are fewer (`6`) but still cover high-impact risks (public DB, unencrypted storage, hardcoded secret).
- Both approaches expose the same core misconfiguration classes: public exposure, weak access controls, missing encryption, poor operational hardening.

### KICS Pulumi Support Evaluation
- KICS correctly auto-detected Pulumi YAML and returned Pulumi-specific cloud checks.
- Output quality was good (JSON + HTML + console summary) and useful for triage.
- Strong for cloud misconfig + secret detection in Pulumi manifests.

### Critical Findings (At Least 5)
1. Public RDS instance in Terraform (`database.tf:17`) and Pulumi (`Pulumi-vulnerable.yaml:104`).
2. Security groups open to internet (`security_groups.tf` ingress/egress with `0.0.0.0/0`).
3. Public S3 ACL and missing effective public access blocking (`main.tf` S3 bucket config).
4. Wildcard IAM permissions (`iam.tf`, `Action: "*"` / broad `ec2:*`, `s3:*`).
5. Hardcoded secrets in IaC (Pulumi YAML + Ansible inventory/playbooks).

### Tool Strengths
- `tfsec`: fast Terraform-focused signal with clear severities and remediation hints.
- `Checkov`: widest Terraform policy coverage and detailed compliance-style checks.
- `Terrascan`: good policy engine and clear domain categories (Data Protection, Infra Security, IAM, Resilience).
- `KICS`: strong cross-framework support; practical for Pulumi + Ansible in one toolchain.

## Task 2 - Ansible Security Scanning (KICS)

### Generated Artifacts
- `labs/lab6/analysis/kics-ansible-results.json`
- `labs/lab6/analysis/kics-ansible-report.html`
- `labs/lab6/analysis/kics-ansible-report.txt`
- `labs/lab6/analysis/ansible-analysis.txt`

### Ansible Security Issues Found
- Total findings: `10`
- Severity:
  - HIGH: `9`
  - LOW: `1`

Most findings are secrets exposure patterns:
- `Passwords And Secrets - Generic Password`
- `Passwords And Secrets - Generic Secret`
- `Passwords And Secrets - Password in URL`
- Plus one best-practice violation: `Unpinned Package Version`

### Best Practice Violations (>=3) and Impact
1. Secrets in plaintext (`inventory.ini`, `deploy.yml`, `configure.yml`):
   - Impact: credential leakage via VCS/logs/artifacts.
2. Password/secret material embedded in URL:
   - Impact: secrets leak in logs, proxies, browser history.
3. Unpinned package version (`state: latest`):
   - Impact: non-deterministic deployments and supply-chain risk.

### KICS Ansible Query Coverage
- KICS effectively applied:
  - secrets-management checks,
  - plaintext credential checks,
  - dependency/version hygiene checks.
- Coverage was strongest on credential hygiene and leakage patterns.

### Remediation Steps
- Move secrets to Ansible Vault / external secret manager; reference via variables.
- Never pass credentials in URLs; use secure token/header flows.
- Pin exact package versions and update by controlled change process.

## Task 3 - Comparative Analysis and Security Insights

### Comprehensive Tool Comparison Matrix
| Criterion | tfsec | Checkov | Terrascan | KICS |
|---|---|---|---|---|
| Total findings | 53 | 78 | 22 | 16 (Pulumi 6 + Ansible 10) |
| Scan speed (observed) | Fast | Medium | Medium | Medium-Slow |
| False positives (observed) | Low-Medium | Medium | Low-Medium | Medium (secret rules can be broad) |
| Report quality | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| Ease of use | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Documentation | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| Platform support | Terraform-centric | Multi-framework | Multi-framework | Multi-framework |
| Output formats used in lab | JSON, text | JSON, compact CLI | JSON, human | JSON, HTML, text |
| CI/CD integration | Easy | Easy-Medium | Medium | Medium |
| Unique strengths | Fast Terraform triage + severity clarity | Broad policy breadth/compliance checks | Clear policy category view | Unified Pulumi+Ansible security scanning |

### Security Category Analysis
Counts below are approximate keyword/category mappings from tool outputs (non-exclusive):

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|---|---:|---:|---:|---:|---:|---|
| Encryption Issues | 7 | 4 | 2 | 1 | 0 | tfsec |
| Network Security | 12 | 16 | 8 | 1 | 0 | Checkov |
| Secrets Management | 0 | 3 | 0 | 1 | 9 | KICS (Ansible) |
| IAM/Permissions | 11 | 27 | 5 | 0 | 0 | Checkov |
| Access Control | 11 | 9 | 4 | 1 | 0 | tfsec |
| Compliance/Best Practices | 13 | 16 | 8 | 3 | 1 | Checkov |

### Top 5 Critical Findings With Remediation Examples
1. Public DB exposure (`publicly_accessible = true`)
   ```hcl
   publicly_accessible = false
   storage_encrypted   = true
   ```
2. Security groups open to world (`0.0.0.0/0` ingress/egress)
   ```hcl
   cidr_blocks = [var.vpc_cidr] # restrict to trusted network
   ```
3. S3 public ACL / weak public-access-block
   ```hcl
   acl = "private"
   block_public_acls       = true
   block_public_policy     = true
   ignore_public_acls      = true
   restrict_public_buckets = true
   ```
4. Wildcard IAM actions/resources
   ```hcl
   actions   = ["s3:GetObject"]
   resources = ["arn:aws:s3:::my-bucket/*"]
   ```
5. Hardcoded secrets in Pulumi/Ansible
   ```yaml
   # Use secret manager / vault reference, not plaintext value
   dbPassword: ${DB_PASSWORD}
   ```

### Tool Selection Guide
- Use `tfsec` early in PR checks for fast Terraform feedback.
- Use `Checkov` for broader policy/compliance gates before merge/deploy.
- Use `Terrascan` when policy-category visibility and compliance mapping are priorities.
- Use `KICS` as a unified scanner for Pulumi + Ansible (and optionally other IaC).

### Lessons Learned
- Different IaC scanners find overlapping but not identical issues; tool diversity improves coverage.
- Severity quality differs by tool (e.g., Checkov output in this run lacked severity field values).
- Secret detection is strongest in KICS Ansible scans; Terraform scanners focus more on cloud misconfig/compliance.

### CI/CD Integration Strategy
1. PR stage: run tfsec + KICS quick scans (fast fail on critical/high).
2. Merge gate: run Checkov + Terrascan full policy scans.
3. Nightly/full pipeline: full KICS Pulumi/Ansible + HTML artifact publishing.
4. Governance: enforce severity thresholds and suppressions as code-reviewed exceptions only.

### Justification
- A single scanner misses classes of risk (e.g., IAM breadth vs secrets leakage vs runtime exposure controls).
- The selected multi-tool strategy balances speed (tfsec), breadth (Checkov), policy categorization (Terrascan), and cross-framework consistency (KICS).
