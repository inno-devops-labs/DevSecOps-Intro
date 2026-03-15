# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Task 1 — Terraform & Pulumi Security Scanning

### Terraform Tool Comparison
Terraform code was scanned using tfsec, Checkov, and Terrascan. Checkov returned the highest number of findings (78), followed by tfsec (53) and Terrascan (22). Checkov is more aggressive in detecting policy violations, including many standard tagging or naming conventions. tfsec provides robust Terraform-specific results, identifying major misconfigurations with low false positives. Terrascan found fewer issues but focuses mainly on compliance mappings.

### Pulumi Security Analysis
Scanning Pulumi with KICS yielded 6 total findings:
- CRITICAL severity: 1 (RDS DB Instance Publicly Accessible)
- HIGH severity: 2 (Generic Password, DynamoDB Table Not Encrypted)
- MEDIUM severity: 1 (EC2 Instance Monitoring Disabled)
- INFO severity: 2 (EBS Optimization, PITR)

### Terraform vs. Pulumi Analysis
Terraform's HCL is highly declarative, meaning issues are directly tied to hardcoded attributes (e.g., `publicly_accessible = true`). Pulumi uses general-purpose languages or YAML. While YAML is also declarative, handling state and secrets can be different. The core issues remain similar (open security groups, plain-text secrets, missing encryption). The scanning tools must interpret either HCL or understand the Pulumi YAML/state representations.

### KICS Pulumi Support
KICS natively supports Pulumi YAML. It automatically discovers Pulumi configuration and can match AWS API resource definitions securely against its unified catalog.

### Critical Findings (Top 5)
1. **Hardcoded Database Passwords**: Found in Pulumi as plaintext secrets (`dbPassword: <SECRET>`).
2. **RDS DB Instance Publicly Accessible**: Found by KICS (CRITICAL).
3. **DynamoDB Table Not Encrypted**: Found by KICS (HIGH).
4. **IAM Wildcard Permissions**: Often flagged by tfsec/Checkov in Terraform as excessive privileges.
5. **Open Security Groups (0.0.0.0/0)**: High severity network risk allowing full public access.

### Tool Strengths
- **tfsec**: Fast, excellent native integration with purely Terraform workflows. 
- **Checkov**: Most comprehensive policy catalog, handles a broader set of DevOps issues like missing tags.
- **Terrascan**: Good for OPA policies and compliance frameworks (e.g., PCI-DSS mappings).
- **KICS (Checkmarx)**: High versatility natively supporting Pulumi YAML and Ansible properly.

---

## Task 2 — Ansible Security Scanning

### Ansible Security Issues
Scanning Ansible with KICS returned 10 total findings, mostly focusing on secrets and package versions:
- HIGH: 9 findings (related to hardcoded passwords and secrets).
- LOW: 1 finding (Unpinned package versions).

### Best Practice Violations
1. **Hardcoded Secrets**: Plaintext passwords stored in variables or inventory files (e.g., `ansible_become_password`). This is a huge risk if code is committed to source control.
2. **Unpinned Package Versions**: Using `state: latest` instead of a specific version can introduce breaking changes or untrusted updates.
3. **Using Root with Default Port**: Attempting to login directly as root over SSH can lead to brute force vulnerabilities.

### KICS Ansible Queries
KICS checks for secrets management, secure command execution, and permission settings. It effectively parsed both task YAMLs (`deploy.yml`) and INI-styled inventory files.

### Remediation Steps
- Replace hardcoded secrets with Ansible Vault (`ansible-vault`).
- Pin package versions in the package manager modules (e.g., `name: myapp=1.2.3`).
- Reconfigure inventory files to avoid root usage; authenticate using ssh keys and utilize `become` safely.

---

## Task 3 — Comparative Tool Analysis & Security Insights

### Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 16 (Pulumi + Ansible) |
| **Scan Speed** | Fast | Medium | Fast | Medium |
| **False Positives** | Low | Medium | Low | Low |
| **Report Quality** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Platform Support** | Terraform | Multiple | Multiple | Multiple |
| **Output Formats** | JSON, text, SARIF | JSON, CLI, SARIF | JSON, YAML, human | JSON, HTML, SARIF |
| **CI/CD Integration** | Easy | Medium | Medium | Medium |

### Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|-------|---------|-----------|---------------|----------------|----------|
| **Encryption Issues** | Excellent | Excellent | Good | Good | N/A | Checkov |
| **Network Security** | Excellent | Excellent | Excellent | Good | Good | tfsec |
| **Secrets Management**| Good | Good | Good | Excellent | Excellent | KICS |
| **IAM/Permissions** | Excellent | Excellent | Good | Good | Good | Checkov |
| **Access Control** | Good | Excellent | Good | Excellent | Excellent | KICS |
| **Compliance** | Good | Excellent | Excellent | Good | Good | Checkov |

### Tool Selection Guide
- Use **tfsec** for quick feedback loops specifically focused on Terraform during local development (pre-commit).
- Use **Checkov** as the primary CI/CD blocking gate for comprehensive checks and policy enforcement across a diverse set of IaC.
- Use **Terrascan** when specific compliance standard audits are strictly required (like PCI-DSS).
- Use **KICS** when dealing seamlessly with complex setups that include missing segments like Ansible playbooks, or Pulumi workflows.

### Lessons Learned
- False positives are higher in tools checking many "best-practice" guidelines (like tagging) than strictly critical security vulnerabilities.
- Unifying multiple IaC paradigms (Terraform vs Pulumi vs Ansible) proves tricky; tools like KICS can centralize the vulnerability management for less-supported domains.

### CI/CD Integration Strategy
- **IDE / Pre-commit**: Implement `tfsec` pre-commit hooks to give developers instant feedback before submitting PRs.
- **CI Pipeline (PR Stage)**: Employ `Checkov` (Terraform/Docs) and `KICS` (Ansible/Pulumi) to automatically verify and enforce security boundaries. Set them up to fail the build upon discovering `HIGH` / `CRITICAL` issues.
- **CD Pipeline (Deployment)**: Utilize `Terrascan` to check the fully generated plans and verify compliance against established company requirements right before applying infrastructure modifications.

### Justification
Choosing multiple tools creates layered defense. `tfsec` is developer-friendly, encouraging early resolution without pipeline friction. Checkov/KICS represent comprehensive CI coverage to catch hard-to-detect or cross-framework flaws. This strategy improves metrics and catches errors at the earliest possible stage (shift-left).
