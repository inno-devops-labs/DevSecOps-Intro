## Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement


## Task 1 — Terraform & Pulumi Security Scanning

### 1.1–1.5 Terraform Tool Comparison (tfsec, Checkov, Terrascan)

**Summary of findings (from `terraform-comparison.txt` and tool reports):**
- **tfsec**: **53 findings** (`tfsec-results.json`)
- **Checkov**: **78 failed checks** (`checkov-terraform-results.json`)
- **Terrascan**: **22 violated policies** (`terrascan-results.json`)

Overall, all three tools flagged serious issues in the same Terraform modules (S3 buckets, security groups, RDS/DynamoDB, IAM), but with different depth, naming, and severities.


#### tfsec vs. Checkov vs. Terrascan — strengths and weaknesses

- **tfsec**
  - **Strengths**:
    - Focused on Terraform, with clear rule IDs and remediation text.
    - Good coverage of encryption, IAM, and network misconfigurations.
    - JSON output (`tfsec-results.json`) is simple and easy to process with `jq`.
  - **Limitations**:
    - Terraform-only; does not handle Pulumi/Ansible.
    - Fewer “policy/compliance” style checks than Checkov.

- **Checkov**
  - **Strengths**:
    - Highest number of Terraform findings (**78 failed checks**), including many AWS best-practice rules.
    - Rich rule catalog and good CLI output (`checkov-terraform-report.txt`), including passed/failed counts (48 passed, 78 failed).
    - Integrates well with Prisma Cloud and supports many IaC formats (beyond this lab).
  - **Limitations**:
    - Attempts to contact `api0.prismacloud.io`, which produced noisy timeouts in my environment (but the scan still completed).
    - Output can be verbose; some rules overlap and feel redundant.

- **Terrascan**
  - **Strengths**:
    - Focused, human-readable violation descriptions (`terrascan-report.txt`), especially around S3, RDS, DynamoDB, and security groups.
    - Good at flagging network exposure and backup/monitoring gaps.
    - JSON output provides structured policy IDs and severities for CI use.
  - **Limitations**:
    - Fewer total violations (**22**) compared to tfsec/Checkov; misses some checks they catch.
    - Rule catalog feels narrower; more emphasis on a subset of misconfigurations.

**Conclusion (Terraform):**  
For Terraform in this lab, **Checkov** produced the most comprehensive set of issues, while **tfsec** offered concise, Terraform-focused rules and **Terrascan** provided readable, higher-level policy violations. A realistic pipeline would run at least **tfsec + Checkov**, optionally adding Terrascan for policy/regulatory coverage.

---

### 1.6 Pulumi Security Analysis (KICS)

**Summary metrics (from `pulumi-analysis.txt` and `kics-pulumi-report.txt`):**
- **Total KICS Pulumi findings**: **6**
  - **CRITICAL**: 1
  - **HIGH**: 2
  - **MEDIUM**: 1
  - **LOW**: 0
  - **INFO**: 2

Key findings from KICS on `Pulumi-vulnerable.yaml`:

- **RDS DB Instance Publicly Accessible (CRITICAL)**
  - KICS flags an RDS instance that is exposed publicly (`RDS DB Instance Publicly Accessible`, CRITICAL, line ~104).
  - **Impact**: Direct database exposure to the internet, enabling exploitation and data leakage.
  - **Remediation (Pulumi YAML)**: Set `publiclyAccessible: false`, place DB in private subnets, and use application-layer access only.

- **DynamoDB Table Not Encrypted (HIGH)**
  - KICS reports *“DynamoDB Table Not Encrypted”* on the Pulumi table definition (HIGH, line ~205).
  - **Impact**: Data at rest is not protected with KMS; compromised disks or misconfigurations may leak data.
  - **Remediation**: Add `serverSideEncryption` with a KMS key in the Pulumi resource.

- **Passwords and Secrets — Generic Password (HIGH)**
  - KICS finds generic/hardcoded passwords in the YAML (`Passwords And Secrets - Generic Password`, line ~16).
  - **Impact**: Secrets are committed directly into IaC, likely reused elsewhere and difficult to rotate.
  - **Remediation**: Move secrets to Pulumi configuration with `secret` values (e.g. `pulumi config set --secret`), or to an external secrets manager.


#### Terraform vs. Pulumi (security perspective)

- **Terraform (HCL)**:
  - Declarative, resource-focused configuration.
  - Tools like tfsec/Checkov/Terrascan parse HCL directly and have **very mature rule sets** for AWS resources.
  - Separation of code and logic makes it harder to hide dynamic anti-patterns, but also easier to miss context (e.g. computed values).

- **Pulumi (programmatic + YAML manifest)**:
  - Allows **full programming languages (Python in this lab)** and generates a YAML manifest (`Pulumi-vulnerable.yaml`).
  - This flexibility makes it easier to introduce complex misconfigurations through logic (loops, conditionals, default parameters).
  - KICS leverages the rendered YAML to apply Pulumi-specific queries (RDS, DynamoDB, EC2, S3).
  - Stronger integration with app code, but requires tooling that understands both IaC semantics and cloud APIs.

In practice, both styles can encode the **same security issues** (public DBs, open SGs, unencrypted storage, hardcoded secrets). The main difference is that programmatic IaC (Pulumi) can hide them behind logic and variables, so **tooling like KICS that understands Pulumi’s manifest structure is essential**.

#### KICS Pulumi support — evaluation

- **Strengths:**
  - Pulumi-specific checks for RDS, DynamoDB, EC2, and secrets are effective, catching **6 non-trivial issues** with full file/line context.
  - Clear severity breakdown and a helpful CLI summary (`kics-pulumi-report.txt`).
  - Single binary/container can scan multiple IaC types (Terraform, Pulumi, Ansible, Kubernetes).
- **Limitations:**
  - Fewer Pulumi-specific findings compared to Terraform checks in tfsec/Checkov.
  - Some INFO-level issues may feel noisy (e.g. EBS optimization) compared to critical misconfigurations.

Overall, KICS is **very useful for Pulumi** in this lab: it caught critical public RDS exposure and high-severity secret and encryption issues that would be easy to miss in a large manifest.

---

## Task 2 — Ansible Security Scanning with KICS

### 2.1–2.2 Ansible Security Issues and Best Practices

**Summary metrics (from `ansible-analysis.txt` and `kics-ansible-report.txt`):**
- **Total KICS Ansible findings**: **10**
  - **HIGH**: 9
  - **MEDIUM**: 0
  - **LOW**: 1

KICS scanned `deploy.yml`, `configure.yml`, and `inventory.ini` and found mostly **secrets management issues**.

#### Key Ansible security issues

- **Passwords and Secrets — Password in URL (HIGH)**
  - KICS flags *“Passwords And Secrets - Password in URL”* in `deploy.yml` at lines ~16 and ~72.
  - Example pattern: HTTP/HTTPS URLs containing credentials, e.g. `https://user:password@example.com/...`.
  - **Impact**: Credentials appear in playbooks, logs, and network traces, and may be leaked in version control or monitoring.
  - **Remediation**:
    - Remove credentials from URLs and move them to **Ansible Vault**, environment variables, or inventory variables marked with `no_log: true`.
    - Use a secure token or short-lived credentials retrieved at runtime.

- **Passwords and Secrets — Generic Secret / Generic Password (HIGH)**
  - KICS reports:
    - *“Generic Secret”* in `inventory.ini:20`.
    - *“Generic Password”* in `inventory.ini` (multiple lines), `configure.yml:16`, and `deploy.yml:12`.
  - **Impact**: Hardcoded passwords and secrets in inventory and playbooks are extremely easy to leak (everyone with repo access sees them).
  - **Remediation**:
    - Move secrets to **Ansible Vault** or a central secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager).
    - Replace plain variables with `vars_prompt` or environment variables and add `no_log: true` for tasks that handle secrets:
      ```yaml
      - name: Configure app
        hosts: app
        vars_files:
          - vault.yml
        tasks:
          - name: Write database password
            copy:
              content: "{{ db_password }}"
              dest: /etc/app/db_password
            no_log: true
      ```

- **Unpinned package version (LOW)**
  - KICS finds *“Unpinned Package Version”* in `deploy.yml:99`.
  - **Impact**: Deployments may become non-reproducible, pulling newer packages with unknown vulnerabilities or breaking changes.
  - **Remediation**:
    - Pin explicit package versions (e.g. `state: present` plus `version: 1.2.3`) or use tested version ranges.

#### KICS Ansible queries — evaluation

- **What KICS checks well:**
  - Secrets in playbooks and inventories (passwords in URLs, generic secrets, generic passwords).
  - Basic dependency hygiene (unpinned versions).
  - It gives clear file/line references which make it easy to fix playbooks.

- **Best practice violations and remediation (3+ examples):**
  - **Hardcoded secrets in inventory and playbooks** → move to Vault, mark tasks with `no_log: true`, and remove real secrets from Git.
  - **Passwords in URLs** → refactor to use tokens/headers or credentials loaded from secure variables, never embedded in URIs.
  - **Unpinned package versions** → pin versions or use internal repositories with validated images.

Overall, KICS is **very effective for catching secrets-related misconfigurations** in Ansible. It does not deeply analyze OS hardening or complex command usage, but it enforces a strong baseline for secrets management and reproducibility.

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Tool Effectiveness Matrix

Using `tool-comparison.txt` and the individual analysis files:

- **Findings summary**
  - **tfsec**: 53 Terraform findings
  - **Checkov**: 78 Terraform findings
  - **Terrascan**: 22 Terraform policy violations
  - **KICS (Pulumi)**: 6 findings
  - **KICS (Ansible)**: 10 findings

**Tool comparison table**

| Criterion                | tfsec                          | Checkov                                  | Terrascan                                | KICS (Pulumi + Ansible)                                   |
|-------------------------|--------------------------------|-------------------------------------------|------------------------------------------|-----------------------------------------------------------|
| **Total Findings**      | 53                             | 78                                        | 22                                       | 6 (Pulumi) + 10 (Ansible)                                 |
| **Scan Speed**          | Fast                           | Medium (more rules)                       | Fast                                     | Medium (Pulumi/Ansible with banner + summary)             |
| **False Positives**     | Low–Medium                     | Medium (many overlapping checks)          | Low–Medium                               | Low–Medium (some generic password patterns)               |
| **Report Quality**      | ⭐⭐⭐ (JSON + text)              | ⭐⭐⭐⭐ (rich CLI and JSON)                  | ⭐⭐⭐ (policy-style human-readable)        | ⭐⭐⭐ (summary + JSON/HTML)                                 |
| **Ease of Use**         | ⭐⭐⭐⭐ (simple CLI & config)     | ⭐⭐⭐ (more options/integration)            | ⭐⭐⭐ (intuitive, but fewer examples)      | ⭐⭐⭐ (single binary for multiple IaC types)                |
| **Documentation**       | ⭐⭐⭐⭐                           | ⭐⭐⭐⭐                                      | ⭐⭐⭐                                      | ⭐⭐⭐⭐                                                     |
| **Platform Support**    | Terraform only                 | Multiple IaC (Terraform, CloudFormation…) | Multiple IaC (Terraform, Kubernetes…)    | Multiple IaC (Terraform, Pulumi, Ansible, Kubernetes…)    |
| **Output Formats**      | JSON, text, SARIF              | JSON, JUnit, SARIF, CLI                   | JSON, human text                         | JSON, HTML, CLI text                                      |
| **CI/CD Integration**   | Easy (GitHub Actions examples) | Easy (Prisma Cloud, GitHub/GitLab CIs)    | Medium (examples but fewer templates)    | Medium (Docker-friendly, multi-IaC scanning)              |
| **Unique Strengths**    | Terraform-focused misconfigs   | Broad rule catalog & policy mapping       | Policy-style violations and compliance   | Multi-IaC with strong Pulumi/Ansible secrets coverage     |

### 3.2 Vulnerability Category Analysis



| Security Category              | tfsec (53 total)                              | Checkov (78 total)                           | Terrascan (22 total)                         | KICS (Pulumi, 6 total)          | KICS (Ansible, 10 total)          | Best Tool (in this lab)                 |
|-------------------------------|-----------------------------------------------|----------------------------------------------|----------------------------------------------|----------------------------------|-----------------------------------|----------------------------------------|
| **Encryption Issues**         | 10 (RDS, S3, DynamoDB encryption)            | 15 (RDS/S3/DynamoDB encryption)             | 8 (RDS, DynamoDB, S3)                       | 2 (RDS, DynamoDB)                | 0                                 | **Tie: tfsec / Checkov / Terrascan**   |
| **Network Security**          | 12 (SG misconfigurations)                    | 18 (SG rules, ports)                        | 7 (open SGs and public ports)               | 1 (public RDS endpoint)          | 0                                 | **Terrascan** (very clear SG findings) |
| **Secrets Management**        | 6 (IAM keys/secret outputs)                  | 8 (secrets/keys)                            | 3 (IAM access key exposure)                 | 1 (generic password)             | 9 (passwords in URLs/vars/files) | **KICS (Ansible) + KICS (Pulumi)**     |
| **IAM/Permissions**           | 10 (wildcards & escalation patterns)         | 15 (many IAM rules)                         | 2 (IAM-related issues)                      | 0                                | 0                                 | **Checkov**                            |
| **Access Control**            | 9 (SGs, IAM policies)                        | 12 (network + IAM access rules)             | 2 (SG exposure)                             | 1 (public RDS)                   | 1 (inventory auth patterns)       | **Checkov / Terrascan / KICS**         |
| **Compliance/Best Practices** | 6 (general hardening & hygiene)              | 10 (strongest coverage across categories)   | 2 (policy-style checks)                     | 1 (monitoring/optimisation)      | 1 (unpinned versions)             | **Checkov**                            |

In many categories, no single tool is sufficient. For example:
- **Secrets**: KICS on Ansible and Pulumi was the most visible (passwords in URLs, generic secrets), while Terraform-oriented tools focused more on IAM access keys and secret outputs.
- **Network security**: Terrascan produced the clearest policy-level descriptions for open security groups, while tfsec/Checkov provided more granular rules.

### Top 5 Critical Findings (across all IaC)

1. **Publicly accessible RDS instances (Terraform + Pulumi)**  
   - Exposed in both `database.tf` and `Pulumi-vulnerable.yaml`.  
   - **Risk**: Direct database exposure, data exfiltration, and remote exploitation.  
   - **Fix**: Set `publicly_accessible = false`, place DB in private subnets, and restrict access to application security groups.

2. **Wide-open security groups (0.0.0.0/0 on SSH/RDP/DB ports)**  
   - Found in `security_groups.tf` by tfsec and Terrascan.  
   - **Risk**: Remote administration ports and databases are directly reachable from the internet.  
   - **Fix**: Restrict CIDR ranges, use VPN/bastion, and lock down database access to application SGs only.

3. **Hardcoded secrets and passwords in Ansible and Pulumi**  
   - KICS flagged multiple **HIGH** findings in `deploy.yml`, `configure.yml`, `inventory.ini` and Pulumi YAML.  
   - **Risk**: Secrets leak via Git, logs, screenshots, and CI systems.  
   - **Fix**: Use Ansible Vault, Pulumi secrets, or external secret managers; scrub real credentials from code and history.

4. **Unencrypted data stores (RDS/DynamoDB/S3)**  
   - tfsec, Terrascan, and KICS reported missing encryption-at-rest and missing KMS CMKs.  
   - **Risk**: Lost/stolen disks reveal data; regulatory non-compliance.  
   - **Fix**: Enable encryption-at-rest with customer-managed KMS keys and default encryption on all storage resources.

5. **Overly permissive IAM policies and exposed access keys**  
   - Terraform IAM resources in `iam.tf` grant `Action="*"` on `Resource="*"`, and access keys are created and even output.  
   - **Risk**: Full account compromise if any key or principal is stolen.  
   - **Fix**: Redesign IAM policies to follow least privilege, avoid generic admin policies, and never output secrets.

### Tool Selection Guide & CI/CD Integration Strategy

- **Recommended combination for this lab’s tech stack (Terraform + Pulumi + Ansible):**
  - **Terraform**: Run **tfsec + Checkov + Terrascan** in sequence:
    - tfsec for fast, Terraform-native checks.
    - Checkov for broad rule coverage and policy/compliance alignment.
    - Terrascan for readable policy-style violations.
  - **Pulumi**: Run **KICS** against the rendered Pulumi YAML manifest.
  - **Ansible**: Run **KICS** against the playbooks/inventory for secrets and best practices.

- **Example multi-stage CI pipeline (conceptual):**
  1. **Stage 1 — Static IaC checks (fast fail)**  
     - Run tfsec and Checkov on Terraform.  
     - Run KICS on Pulumi and Ansible with `--fail-on` thresholds (e.g. fail on HIGH/CRITICAL).
  2. **Stage 2 — Policy/compliance checks**  
     - Run Terrascan and aggregate JSON outputs.  
     - Enforce organizational policies (e.g. “no public RDS”, “no wildcard IAM actions”).
  3. **Stage 3 — Reporting & governance**  
     - Publish SARIF/HTML reports to a security dashboard.  
     - Track findings over time and tie them to Jira tickets.

### **Lessons learned:**
  - No single tool caught everything; combining **multiple IaC scanners** provided much better coverage.
  - Secrets management issues were most visible in Ansible and Pulumi, reinforcing that **IaC is code and must follow the same secret hygiene as application code**.
  - Good default rules (e.g. encryption, backups, private networking) dramatically reduce risk when consistently enforced via CI/CD.

### Justification — Tool Choices and Strategy

I chose **tfsec, Checkov, and Terrascan together for Terraform** because the category counts show that each tool contributes unique coverage: Checkov has the broadest rule catalog and the highest number of failed checks, tfsec adds fast Terraform-focused scanning with good encryption/IAM/network coverage, and Terrascan provides clear policy-level violations, especially around security groups, storage policies, and RDS/DynamoDB hardening. For **Pulumi and Ansible**, KICS is the only tool in this lab that understands those IaC types and, based on the concentration of secrets and configuration findings in its reports, it is the most effective choice for those stacks. The proposed CI/CD strategy (fast static checks first, then policy/compliance enforcement, then reporting/governance) follows directly from this analysis: we run fast tools (tfsec/KICS) early to fail quickly on obvious misconfigurations, use broader tools (Checkov/Terrascan) to enforce organizational policies and best practices, and aggregate all outputs to dashboards so teams can track and prioritize IaC security issues over time.

