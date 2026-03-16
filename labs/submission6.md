# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

# Task 1 — Terraform & Pulumi Security Scanning

## 1.1 Scanning Setup

I created a dedicated analysis directory and used Docker-based scanners to ensure a reproducible and isolated environment.

```bash
mkdir -p labs/lab6/analysis
```

This approach made it possible to run all tools without installing them locally and ensured consistent scanner versions.

---

## 1.2 Terraform Scan with tfsec

I scanned the vulnerable Terraform code with tfsec and generated both JSON and readable text reports.

**Artifacts:**

* `labs/lab6/analysis/tfsec-results.json`
* `labs/lab6/analysis/tfsec-report.txt`

**Result summary:**

* **tfsec findings:** **53**

### Observations

tfsec detected a broad range of AWS security issues, especially around:

* storage security
* network exposure
* database misconfiguration
* weak infrastructure defaults

Examples from the results:

* `AVD-AWS-0023` — **Table encryption is not enabled** (`database.tf`)
* `AVD-AWS-0024` — **Point-in-time recovery is not enabled** (`database.tf`)
* `AVD-AWS-0104` — **Security group rule allows egress to multiple public internet addresses** (`security_groups.tf`)
* `AVD-AWS-0107` — **Security group rule allows ingress from public internet** (`security_groups.tf`)

### tfsec strengths

* Fast execution
* Terraform-specific checks
* Good detection of AWS misconfigurations
* Clear findings with useful severity levels
* Low friction for CI/CD integration

---

## 1.3 Terraform Scan with Checkov

I scanned the same Terraform code with Checkov.

**Artifacts:**

* `labs/lab6/analysis/checkov-terraform-results.json`
* `labs/lab6/analysis/checkov-terraform-report.txt`

**Result summary:**

* **Checkov findings:** **78**

### Observations

Checkov reported the highest number of Terraform findings among the three Terraform scanners. It identified many issues in `database.tf` and also covered broader best-practice and governance-related checks.

Examples from the results:

* `CKV_AWS_118` — **Ensure that enhanced monitoring is enabled for Amazon RDS instances**
* `CKV_AWS_161` — **Ensure RDS database has IAM authentication enabled**
* `CKV_AWS_133` — **Ensure that RDS instances has backup policy**
* `CKV_AWS_17` — **Ensure all data stored in RDS is not publicly accessible**
* `CKV_AWS_16` — **Ensure all data stored in the RDS is securely encrypted at rest**
* `CKV_AWS_293` — **Ensure that AWS database instances have deletion protection enabled**
* `CKV_AWS_226` — **Ensure DB instance gets all minor upgrades automatically**

### Checkov strengths

* Broad built-in policy catalog
* Strong coverage of Terraform best practices
* Very useful for compliance-oriented checks
* Helpful in multi-framework environments

---

## 1.4 Terraform Scan with Terrascan

I scanned the Terraform code with Terrascan.

**Artifacts:**

* `labs/lab6/analysis/terrascan-results.json`
* `labs/lab6/analysis/terrascan-report.txt`

**Result summary:**

* **Terrascan findings:** **22**

### Observations

Terrascan reported fewer findings than tfsec and Checkov, but its results were focused and useful from a compliance/policy perspective.

Examples from the results:

* `rdsIamAuthEnabled` — **Ensure that your RDS database has IAM Authentication enabled**
* `allUsersReadAccess` — **Misconfigured S3 buckets can leak private information to the entire internet**
* `programmaticAccessCreation` — **Ensure that there are no exposed Amazon IAM access keys**
* `port22OpenToInternet` — **Security Groups - Unrestricted Specific Ports - SSH**
* `port3306AlbNetworkPortSecurity` — **Security Groups - Unrestricted Specific Ports - MySQL**
* `rdsBackupDisabled` — **Ensure automated backups are enabled for AWS RDS instances**
* `portWideOpenToPublic` — **Ensure no security group is wide open to public**
* `iamUserInlinePolicy` — **Ensure IAM policies are attached only to groups or roles**

### Terrascan strengths

* OPA-oriented policy style
* Good compliance and governance focus
* Strong signal on risky exposure patterns
* Useful for organizations that rely on policy-as-code

---

## 1.5 Terraform Tool Comparison

### Summary of findings

| Tool      | Findings |
| --------- | -------- |
| tfsec     | 53       |
| Checkov   | 78       |
| Terrascan | 22       |

### Comparative analysis

The three Terraform tools detected overlapping but non-identical sets of issues.

* **tfsec** was the most focused Terraform scanner. It clearly highlighted cloud resource misconfigurations such as missing encryption and dangerous security group rules.
* **Checkov** reported the largest number of findings. It was especially strong on broader AWS best practices, governance, database hardening, and operational controls.
* **Terrascan** produced fewer findings, but its output was more policy/compliance-oriented and useful for enforcing organizational standards.

### Why the counts differ

The finding counts differ because each scanner uses:

* different rule catalogs
* different parsing logic
* different severity mapping
* different priorities between direct security issues and best-practice/compliance checks

This is expected in IaC security analysis and demonstrates why layered scanning improves coverage.

---

## 1.6 Pulumi Scan with KICS

I scanned the vulnerable Pulumi code using KICS. KICS successfully analyzed the Pulumi YAML manifest and produced JSON, HTML, and console-style output.

**Artifacts:**

* `labs/lab6/analysis/kics-pulumi-results.json`
* `labs/lab6/analysis/kics-pulumi-report.html`
* `labs/lab6/analysis/kics-pulumi-report.txt`

**Result summary:**

* **Total findings:** **6**
* **CRITICAL:** **1**
* **HIGH:** **2**
* **MEDIUM:** **1**
* **LOW:** **0**
* **INFO:** **2**

### Key findings

Examples from the KICS Pulumi results:

* **RDS DB Instance Publicly Accessible** — `CRITICAL`
* **DynamoDB Table Not Encrypted** — `HIGH`
* **Passwords And Secrets - Generic Password** — `HIGH`
* **EC2 Instance Monitoring Disabled** — `MEDIUM`
* **DynamoDB Table Point In Time Recovery Disabled** — `INFO`
* **EC2 Not EBS Optimized** — `INFO`

The most severe issue was:

* **RDS DB Instance Publicly Accessible** in `Pulumi-vulnerable.yaml` line 104
  KICS reported that `publiclyAccessible` was set to `true`, which makes the database reachable over a public interface.

### KICS Pulumi support evaluation

KICS demonstrated useful Pulumi support because it:

* correctly parsed the Pulumi YAML manifest
* mapped findings to specific resource types and lines
* assigned severities and categories
* identified both direct security issues and operational weaknesses

This confirms that KICS is a practical scanner for Pulumi YAML, especially when a team wants consistent scanning across multiple IaC formats.

---

## 1.7 Terraform vs Pulumi Security Analysis

Terraform and Pulumi exposed many of the same cloud security issues because both ultimately define infrastructure resources that can be misconfigured in similar ways.

### Common issue classes across both

* missing encryption
* open network access
* publicly exposed services
* weak access control
* hardcoded secrets

### Differences

**Terraform (HCL):**

* more mature ecosystem of Terraform-specific scanners
* direct static analysis is simpler for tools like tfsec
* strong support for best-practice and compliance scanning

**Pulumi (YAML in this lab):**

* still declarative in this specific scan target, but less commonly used than HCL
* benefited from KICS’s platform-aware Pulumi query catalog
* showed that cross-platform scanners can be effective outside Terraform-only workflows

### Conclusion

The underlying security risks remain mostly the same across IaC technologies. The main difference is scanner maturity and specialization:

* Terraform benefits from specialized tooling
* Pulumi benefits from flexible cross-platform scanners like KICS

---

## 1.8 Critical Findings

### 1. Publicly accessible RDS instance

**Where:** Pulumi (`Pulumi-vulnerable.yaml`) and Terraform database-related findings
**Risk:** The database can be reached over a public interface.
**Impact:** Unauthorized access attempts, brute-force attacks, increased exposure to compromise.
**Remediation:** Set `publiclyAccessible = false`, place the database in private subnets, and restrict access using private security groups only.

**Example fix:**

```hcl
resource "aws_db_instance" "secure_db" {
  publicly_accessible = false
  storage_encrypted   = true
}
```

---

### 2. Missing database/storage encryption

**Where:** Terraform and Pulumi
**Risk:** Data at rest is not protected.
**Impact:** Snapshot leakage, storage compromise, regulatory non-compliance.
**Remediation:** Enable encryption for RDS, DynamoDB, EBS, and S3 resources and use KMS where possible.

**Example fix:**

```hcl
resource "aws_db_instance" "secure_db" {
  storage_encrypted = true
}
```

---

### 3. Security groups open to the public internet

**Where:** `security_groups.tf`
**Risk:** Management and service ports are reachable from `0.0.0.0/0`.
**Impact:** Brute-force attacks, unauthorized access, exploitation of exposed services.
**Remediation:** Limit ingress to trusted CIDR ranges or internal networks only.

**Example fix:**

```hcl
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/24"]
}
```

---

### 4. Hardcoded secrets in code and configuration

**Where:** Pulumi and Ansible
**Risk:** Passwords or keys stored directly in source files can leak via Git history, logs, artifacts, or screenshots.
**Impact:** Credential compromise and unauthorized access.
**Remediation:** Use AWS Secrets Manager, SSM Parameter Store, environment variables, or Ansible Vault.

**Example remediation for Ansible:**

```yaml
vars_files:
  - vault.yml
```

---

### 5. Weak IAM design / excessive permissions

**Where:** Terraform IAM findings
**Risk:** Overly permissive access allows privilege escalation or unrestricted resource access.
**Impact:** Full account compromise, data theft, abuse of cloud resources.
**Remediation:** Replace wildcard permissions with least-privilege actions and resource scopes.

**Example fix:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::example-bucket/*"]
    }
  ]
}
```

---

# Task 2 — Ansible Security Scanning with KICS

## 2.1 KICS Scan of Ansible Playbooks

I used KICS to scan the vulnerable Ansible directory.

**Artifacts:**

* `labs/lab6/analysis/kics-ansible-results.json`
* `labs/lab6/analysis/kics-ansible-report.html`
* `labs/lab6/analysis/kics-ansible-report.txt`

**Result summary:**

* **Total findings:** **10**
* **CRITICAL:** **0**
* **HIGH:** **9**
* **MEDIUM:** **0**
* **LOW:** **1**

### Key observations

KICS scanned 3 files and reported 10 findings in total. Most of them were **HIGH severity**, which indicates that the Ansible code contains directly exploitable or high-impact security weaknesses.

From the JSON report, one of the clearly identified findings was:

* **Passwords And Secrets - Generic Password** — `HIGH`

This affected:

* `configure.yml`
* `inventory.ini`

This is consistent with the intentionally vulnerable structure of the lab, where plaintext credentials and insecure operational practices were embedded in playbooks and inventory.

---

## 2.2 Ansible Security Issues

The Ansible scan highlighted several classes of security problems:

* hardcoded passwords and secrets
* secrets present in inventory
* unsafe handling of credentials in configuration
* weak operational security practices
* insecure automation patterns that could leak secrets or expose systems

Based on the vulnerable lab content and the KICS findings, the major Ansible risk domains were:

* **secrets management**
* **access control**
* **unsafe configuration**
* **operational security hygiene**

---

## 2.3 Best Practice Violations

### 1. Hardcoded secrets in playbooks and inventory

**Problem:** Sensitive credentials were stored directly in Ansible files.
**Impact:** Secrets can leak through source control, CI artifacts, logs, and developer environments.
**Fix:** Store secrets in **Ansible Vault** or an external secret manager.

---

### 2. Sensitive values not properly protected

**Problem:** Secret values in Ansible automation are often exposed in variables or task output when not protected.
**Impact:** Passwords and tokens can appear in CI logs or console output.
**Fix:** Add `no_log: true` to sensitive tasks and avoid plaintext secret variables.

**Example:**

```yaml
- name: Configure database password
  ansible.builtin.shell: some-command
  no_log: true
```

---

### 3. Insecure inventory design

**Problem:** Credentials stored in `inventory.ini` create a centralized plaintext exposure point.
**Impact:** Easy credential theft and environment compromise.
**Fix:** Remove passwords and private-key references from plaintext inventory where possible and use Vault or secure runtime injection.

---

## 2.4 KICS Ansible Query Evaluation

KICS performed useful Ansible-focused checks in these categories:

* secret detection
* insecure configuration discovery
* inventory hygiene
* access control and credential exposure
* general security misconfiguration checks

KICS is especially valuable here because it provides a **single scanning approach** for both:

* **Pulumi YAML**
* **Ansible**

This reduces tool fragmentation in DevSecOps pipelines.

---

## 2.5 Remediation Steps

Recommended fixes for the Ansible findings:

1. Move all secrets to **Ansible Vault**
2. Remove plaintext passwords from `inventory.ini`
3. Add `no_log: true` to tasks that handle credentials or tokens
4. Replace unsafe or overly generic automation steps with safer module-based tasks
5. Review SSH and privilege escalation settings
6. Enforce stricter separation between development and production credentials
7. Store sensitive values outside version-controlled files

---

# Task 3 — Comparative Tool Analysis & Security Insights

## 3.1 Comprehensive Tool Comparison

### Summary statistics

| Tool      | Framework | Findings |
| --------- | --------- | -------- |
| tfsec     | Terraform | 53       |
| Checkov   | Terraform | 78       |
| Terrascan | Terraform | 22       |
| KICS      | Pulumi    | 6        |
| KICS      | Ansible   | 10       |

### Tool comparison matrix

| Criterion             | tfsec                   | Checkov                | Terrascan               | KICS                            |
| --------------------- | ----------------------- | ---------------------- | ----------------------- | ------------------------------- |
| **Total Findings**    | 53                      | 78                     | 22                      | 16 (Pulumi + Ansible)           |
| **Scan Speed**        | Fast                    | Medium                 | Medium                  | Medium                          |
| **False Positives**   | Low                     | Medium                 | Medium                  | Medium                          |
| **Report Quality**    | ⭐⭐⭐                     | ⭐⭐⭐⭐                   | ⭐⭐⭐                     | ⭐⭐⭐⭐                            |
| **Ease of Use**       | ⭐⭐⭐⭐                    | ⭐⭐⭐                    | ⭐⭐⭐                     | ⭐⭐⭐                             |
| **Documentation**     | ⭐⭐⭐                     | ⭐⭐⭐⭐                   | ⭐⭐⭐                     | ⭐⭐⭐                             |
| **Platform Support**  | Terraform-focused       | Multiple               | Multiple                | Multiple                        |
| **Output Formats**    | JSON, text, SARIF       | JSON, CLI, SARIF, more | JSON, human             | JSON, HTML, text, SARIF         |
| **CI/CD Integration** | Easy                    | Easy                   | Medium                  | Easy                            |
| **Unique Strengths**  | Fast Terraform scanning | Broad policy catalog   | Compliance/policy angle | Strong Pulumi + Ansible support |

---

## 3.2 Vulnerability Category Analysis

| Security Category             | tfsec  | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool           |
| ----------------------------- | ------ | ------- | --------- | ------------- | -------------- | ------------------- |
| **Encryption Issues**         | Strong | Strong  | Strong    | Strong        | Limited        | Checkov / KICS      |
| **Network Security**          | Strong | Strong  | Strong    | Medium        | Limited        | tfsec / Terrascan   |
| **Secrets Management**        | Medium | Medium  | Medium    | Strong        | Strong         | KICS                |
| **IAM/Permissions**           | Strong | Strong  | Strong    | Limited       | N/A            | Checkov / tfsec     |
| **Access Control**            | Strong | Strong  | Strong    | Strong        | Medium         | Checkov             |
| **Compliance/Best Practices** | Medium | Strong  | Strong    | Medium        | Medium         | Terrascan / Checkov |

### Analysis by category

* **Encryption:** tfsec, Checkov, and Terrascan all identified missing encryption in Terraform resources. KICS also detected encryption weaknesses in Pulumi, including an unencrypted DynamoDB table.
* **Network security:** tfsec and Terrascan were especially strong at identifying public internet exposure and dangerous security group patterns.
* **Secrets management:** KICS was the strongest tool for secrets-related findings in this lab because it directly detected hardcoded password-like values in both Pulumi and Ansible.
* **IAM/permissions:** tfsec, Checkov, and Terrascan all highlighted risky IAM-related patterns, but Checkov and tfsec provided the strongest practical coverage.
* **Compliance/best practices:** Checkov and Terrascan were strongest in this area because they include many operational and governance-oriented checks.

---

## 3.3 Top 5 Critical Findings

1. Publicly accessible RDS instance
2. Missing encryption for databases and tables
3. Security groups open to the internet
4. Hardcoded passwords and secrets
5. Excessive IAM permissions

These findings are critical because they directly increase the likelihood of:

* unauthorized access
* data exposure
* privilege escalation
* infrastructure compromise
* compliance violations

---

## 3.4 Tool Selection Guide

### tfsec

Best when:

* the codebase is primarily Terraform
* fast feedback is required
* teams want a focused Terraform scanner with low setup overhead

### Checkov

Best when:

* broader policy coverage is needed
* teams use multiple infrastructure technologies
* compliance and best-practice coverage is important

### Terrascan

Best when:

* policy-as-code and governance matter
* organizations want compliance-oriented enforcement
* teams use OPA-style thinking for security policy

### KICS

Best when:

* Pulumi YAML must be scanned
* Ansible scanning is required
* one tool should cover multiple IaC and automation formats

### Recommended strategy

A practical DevSecOps approach for this lab would be:

* **tfsec + Checkov** for Terraform
* **KICS** for Pulumi and Ansible
* **Terrascan** as an additional compliance-focused gate

---

## 3.5 Lessons Learned

1. No single tool provides complete coverage.
2. Different scanners identify overlapping but not identical findings.
3. Terraform-specific tools are stronger for Terraform than generic scanners alone.
4. KICS is especially valuable when scanning Pulumi YAML and Ansible together.
5. Finding count alone does not determine usefulness; policy depth and category coverage also matter.
6. Combining focused scanners with broader policy/compliance scanners gives the best overall visibility.

---

## 3.6 CI/CD Integration Strategy

A practical multi-stage pipeline could be structured as follows:

### Stage 1 — Developer / pre-commit

* run **tfsec** for quick Terraform feedback
* run **KICS** locally for Pulumi and Ansible checks

### Stage 2 — Pull request

* run **Checkov** for comprehensive Terraform scanning
* run **KICS** for Pulumi and Ansible
* fail the pipeline on critical/high findings

### Stage 3 — Release / compliance gate

* run **Terrascan** for compliance-oriented validation
* optionally add custom OPA/Conftest rules for organization-specific policies
* require manual review for unresolved high-risk findings

### Merge policy recommendation

* block merge on **critical/high**
* require review or risk acceptance for some **medium**
* track **low** issues in backlog when they do not create immediate exploitability

---

## 3.7 Justification

My recommended scanning strategy is based on balancing:

* speed
* security coverage
* platform support
* policy depth
* CI/CD practicality

**tfsec** is best for fast Terraform feedback.
**Checkov** provides the broadest Terraform coverage in this lab.
**Terrascan** adds a valuable compliance and policy-enforcement perspective.
**KICS** is the most practical single choice for **Pulumi YAML** and **Ansible**.
