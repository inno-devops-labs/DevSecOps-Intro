# Lab 6 -  Infrastructure-as-Code Security Analysis

## Task 1: Terraform & Pulumi Security Scanning

### 1.1 Terraform Tool Comparison (tfsec vs. Checkov vs. Terrascan)

The vulnerable Terraform code was scanned using three different tools: `tfsec`, `Checkov`, and `Terrascan`.

**Scan Results Summary:**

| Tool      | Total Findings |
| :-------- | :------------- |
| **tfsec** | 53             |
| **Checkov** | 78             |
| **Terrascan** | 22             |

*Source: `labs/lab6/analysis/terraform-comparison.txt`*

**Analysis:**
- **Checkov** reported the highest number of findings (78), demonstrating the most extensive policy library and broadest coverage.
- **tfsec** was a close second with 53 findings, focusing on high-confidence, Terraform-specific issues.
- **Terrascan** reported the fewest findings (22), indicating a more focused, compliance-oriented ruleset.

### 1.2 Pulumi Security Analysis (KICS)

The vulnerable Pulumi YAML code was scanned using KICS, which provides first-class support for Pulumi.

**Scan Results Summary:**

| Severity | Finding Count |
| :------- | :------------ |
| CRITICAL | 1             |
| HIGH     | 2             |
| MEDIUM   | 1             |
| LOW      | 0             |
| INFO     | 2             |
| **Total**  | **6**           |

*Source: `labs/lab6/analysis/pulumi-analysis.txt`*

**Key Findings:**
- **CRITICAL:** Hardcoded secrets (e.g., database password) were identified in `Pulumi-vulnerable.yaml`.
- **HIGH:** Publicly exposed S3 buckets and insecure security group rules were detected.
- **MEDIUM:** Lack of encryption on S3 buckets.

### 1.3 Terraform vs. Pulumi Security Comparison

- **Declarative (Terraform HCL) vs. Programmatic (Pulumi YAML):** Both IaC approaches were susceptible to similar classes of vulnerabilities, such as hardcoded secrets and insecure network configurations. This shows that the underlying security principles are language-agnostic.
- **Tooling:** Terraform has a more mature ecosystem of specialized scanners (`tfsec`). Pulumi's security scanning relies on general-purpose tools like KICS that have added Pulumi support.
- **KICS Pulumi Support:** KICS demonstrated effective analysis of Pulumi YAML, correctly identifying critical misconfigurations like hardcoded secrets and public S3 buckets. Its ability to parse Pulumi's structure is a significant advantage for teams using Pulumi.

### 1.4 Top 5 Critical Findings (Terraform & Pulumi)

Across both Terraform and Pulumi, several critical vulnerabilities were consistently identified by the scanning tools.

1.  **Hardcoded Secrets in Code (CRITICAL)**
    - **Description:** AWS credentials, database passwords, and other secrets were hardcoded directly in `.tf` files and Pulumi's YAML manifest. This is a top IaC risk as it exposes secrets to anyone with code access.
    - **Detection:** Found by `tfsec`, `Checkov`, and `KICS`. KICS was particularly effective at finding secrets in both Pulumi and Ansible code.
    - **Remediation:** Use a dedicated secrets manager like HashiCorp Vault, AWS Secrets Manager, or the native secrets provider for the IaC tool (e.g., Pulumi Secrets, Ansible Vault).

2.  **Publicly Exposed S3 Buckets (CRITICAL)**
    - **Description:** S3 buckets were configured with `acl = "public-read"`, making their contents accessible to the entire internet. This is a common cause of major data breaches.
    - **Detection:** Found by `tfsec`, `Checkov`, and `Terrascan`.
    - **Remediation:** Remove the public ACL and apply an `aws_s3_bucket_public_access_block` resource to enforce private access by default.

3.  **Overly Permissive Security Group Ingress (CRITICAL)**
    - **Description:** Security groups were configured to allow inbound traffic from `0.0.0.0/0` (any IP address) on sensitive ports like SSH (22) and RDP (3389). This exposes administrative interfaces to brute-force attacks.
    - **Detection:** Found by `tfsec`, `Checkov`, and `Terrascan`.
    - **Remediation:** Restrict ingress to known, trusted IP ranges. Avoid using `0.0.0.0/0` for anything other than public web traffic (ports 80, 443).

4.  **Unencrypted Storage Resources (HIGH)**
    - **Description:** Resources like S3 buckets, RDS database instances, and EBS volumes were provisioned without server-side encryption enabled. This violates compliance standards and puts data at risk if physical storage is compromised.
    - **Detection:** Found by `tfsec` and `Checkov`.
    - **Remediation:** Explicitly enable server-side encryption for all storage resources. For S3, use `aws_s3_bucket_server_side_encryption_configuration`. For RDS and EBS, set the `encrypted` attribute to `true`.

5.  **Overly Permissive IAM Policies (HIGH)**
    - **Description:** IAM roles and policies were created with wildcard permissions (e.g., `Action: "s3:*"` on `Resource: "*"`). This violates the principle of least privilege and can lead to catastrophic data loss or system compromise if the role is assumed by an attacker.
    - **Detection:** Found by `Checkov` and `tfsec`.
    - **Remediation:** Scope IAM policies to the minimum required actions and resources. Avoid wildcards (`*`) wherever possible.

### 1.5 Tool Strengths and Specializations

-   **tfsec:** Excels at **fast, developer-friendly feedback** for Terraform. Its low false-positive rate and clear output make it ideal for pre-commit hooks and rapid CI/CD checks. It is highly specialized for Terraform code.

-   **Checkov:** The **most comprehensive policy library**. Its strength lies in broad coverage across multiple frameworks (Terraform, Kubernetes, etc.) and deep inspection of resource relationships using its graph-based model. It is best for enforcing a wide range of security and compliance policies.

-   **Terrascan:** Best for **compliance-focused scanning**. Its ability to map findings to specific compliance standards (like CIS, PCI-DSS) makes it valuable for audit and governance purposes. Its use of the OPA engine allows for flexible, custom policy creation.

-   **KICS:** A **versatile multi-framework scanner**. Its unique strength is its first-class support for a wide array of IaC tools, including Pulumi and Ansible, which are not covered by the more Terraform-centric scanners. This makes it an excellent choice for teams using a diverse set of IaC technologies.

---

## Task 2: Ansible Security Scanning with KICS

### 2.1 Ansible Security Issues Identified by KICS

KICS proved effective at identifying critical security flaws in the Ansible playbooks.

**Scan Results Summary:**

| Severity | Finding Count |
| :------- | :------------ |
| HIGH     | 9             |
| MEDIUM   | 0             |
| LOW      | 1             |
| **Total**  | **10**          |

*Source: `labs/lab6/analysis/ansible-analysis.txt` & `labs/lab6/analysis/kics-ansible-results.json`*

**Key Security Problems Found:**
- **Hardcoded Secrets (9 HIGH findings):** KICS excelled at finding plaintext credentials, including passwords and API keys, across multiple files (`configure.yml`, `deploy.yml`, and `inventory.ini`). This is a critical risk (CWE-798) that could lead to immediate system compromise.
- **Use of `latest` Tag (1 LOW finding):** The scanner flagged the use of `state: latest` for package installation. This practice can introduce non-deterministic behavior and automatically deploy newly vulnerable package versions without review.
- **Insecure Command Execution:** The playbooks contain risky patterns like using the `shell` module instead of specific Ansible modules. While not all were flagged by default KICS rules, these patterns are inherently dangerous as they can be vectors for command injection.

### 2.2 KICS Ansible Query Evaluation

KICS applies a comprehensive set of queries specifically designed for Ansible, covering major risk categories:
- **Secrets Management:** Detects hardcoded passwords, private keys, and API tokens. This was its strongest area in the scan.
- **Insecure Defaults:** Flags insecure default settings, such as creating files with world-writable permissions.
- **Command Injection Risks:** Identifies the use of `shell` or `command` modules where safer, purpose-built modules should be used.
- **Authentication & Authorization:** Checks for weak SSH configurations, passwordless sudo, and other privilege escalation risks.
- **Best Practices:** Enforces best practices like pinning package versions and avoiding the `latest` tag.

Overall, the KICS query catalog for Ansible is robust, focusing on high-impact, real-world vulnerabilities common in configuration management scripts.

### 2.3 Best Practice Violations and Remediation

Three major best practice violations were identified, with clear remediation paths.

1.  **Violation: Hardcoded Secrets in Playbooks and Inventory**
    - **Impact:** Exposing credentials in version control allows any developer (or attacker with repository access) to compromise target systems. This is one of the most common and dangerous IaC risks.
    - **Remediation:** Use **Ansible Vault** to encrypt sensitive files or individual variables. This integrates secrets securely into the Ansible workflow.
      ````yaml
      # 1. Encrypt a variables file
      ansible-vault encrypt vars/secrets.yml

      # 2. Reference the vaulted file in the playbook
      - hosts: all
        vars_files:
          - vars/secrets.yml # Ansible decrypts this at runtime with the vault password
        tasks:
          - name: Configure database
            community.postgresql.postgresql_user:
              password: "{{ db_password }}" # Uses the vaulted variable
      ````

2.  **Violation: Missing `no_log: true` for Tasks Handling Secrets**
    - **Impact:** Without this flag, Ansible's default logging behavior will print task inputs and outputs to the console and log files. This can inadvertently expose the very secrets you are trying to protect with Ansible Vault.
    - **Remediation:** Add `no_log: true` to any task that creates, updates, or uses sensitive data.
      ````yaml
      # As seen in lectures/lec6.md
      - name: Set root password
        user:
          name: root
          password: "{{ root_password | password_hash('sha512') }}"
        no_log: true # ✅ Prevents the hashed password from being logged
      ````

3.  **Violation: Using `shell` Module Instead of Purpose-Built Modules**
    - **Impact:** The `shell` and `command` modules are generic and do not validate inputs in the context of the target system. This makes them susceptible to command injection if they use external variables. They are also less idempotent and produce less structured output.
    - **Remediation:** Always prefer specific, built-in Ansible modules (`apt`, `user`, `copy`, `template`, etc.) over `shell`. They provide better validation, idempotency, and error handling.
      ````yaml
      # ❌ BAD: Insecure and not idempotent
      - name: Install nginx via shell
        ansible.builtin.shell: apt-get install -y nginx

      # ✅ GOOD: Secure, idempotent, and provides clear state management
      - name: Install nginx via apt module
        ansible.builtin.apt:
          name: nginx
          state: present
      ````
---

## Task 3: Comparative Tool Analysis & Security Insights

### 3.1 Comprehensive Tool Effectiveness Matrix

This matrix evaluates each tool across several key criteria based on the results from scanning the vulnerable IaC code.

| Criterion          | tfsec                               | Checkov                             | Terrascan                           | KICS (for Pulumi/Ansible)           |
| :----------------- | :---------------------------------- | :---------------------------------- | :---------------------------------- | :---------------------------------- |
| **Total Findings** | **53**                 | **78**                  | **22**                  | **16**      |
| **Scan Speed**     | ⚡️ Fast (~5s)                       | 🐢 Medium (~15s)                    | 🐢 Medium (~12s)                    | ⚡️ Fast (~8s per framework)         |
| **False Positives**| Low                                 | Low-Medium                          | Medium                              | Low-Medium                          |
| **Report Quality** | ⭐⭐⭐⭐ (Clear & concise)            | ⭐⭐⭐⭐ (Very detailed, graph-based)  | ⭐⭐⭐ (Compliance-focused)           | ⭐⭐⭐⭐ (Good detail, HTML report)    |
| **Ease of Use**    | ⭐⭐⭐⭐⭐ (Single binary, simple)      | ⭐⭐⭐⭐ (Easy, Python-based)        | ⭐⭐⭐⭐ (Easy, Go-based)            | ⭐⭐⭐⭐ (Easy via Docker)           |
| **Platform Support** | Terraform only                      | Multiple (TF, K8s, Docker, etc.)    | Multiple (TF, K8s, etc.)            | Multiple (TF, Pulumi, Ansible, etc.)|
| **Output Formats** | JSON, SARIF, text, JUnit            | JSON, SARIF, text, JUnit, CycloneDX | JSON, YAML, XML, SARIF              | JSON, SARIF, HTML, CycloneDX, PDF   |
| **CI/CD Integration**| Easy                                | Easy                                | Easy                                | Easy                                |
| **Unique Strengths**| Speed, low false positives, TF-native | Broadest policy library, graph model | OPA-based, strong compliance mapping | **Multi-tool support (Pulumi, Ansible)**|
| **Documentation**  | ⭐⭐⭐⭐ (Good, well-structured)       | ⭐⭐⭐⭐⭐ (Excellent, extensive)     | ⭐⭐⭐ (Good, but less examples)      | ⭐⭐⭐⭐ (Good, well-organized)        |


### 3.2 Vulnerability Category Analysis


| Security Category        | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool(s)        |
| :----------------------- | :---: | :-----: | :-------: | :-----------: | :------------: | :------------------ |
| **Encryption Issues**    | 8     | 12      | 6         | 1             | N/A            | **Checkov**         |
| **Network Security**     | 15    | 21      | 8         | 1             | 0              | **Checkov, tfsec**  |
| **Secrets Management**   | 4     | 4       | 0         | 1             | 9              | **KICS**            |
| **IAM/Permissions**      | 6     | 10      | 2         | 0             | N/A            | **Checkov**         |
| **Logging & Monitoring** | 5     | 8       | 1         | 1             | 0              | **Checkov**         |
| **Compliance/Best Practice** | 15    | 23      | 5         | 2             | 1              | **Checkov**         |

**Key Insights from Real Data:**
- **Defense-in-Depth Works:** No single tool found all issues. `Checkov` had the best overall coverage for Terraform (78 findings), but `KICS` was essential for finding the majority of secrets (10 total) across all frameworks.
- **Specialization Matters:** `tfsec` is the best for quick, developer-centric feedback on Terraform. `KICS` is indispensable for teams with a mixed-tool environment. `Terrascan` is ideal for formal compliance audits but has significant gaps.
- **Critical Blind Spot:** `Terrascan` completely missed all 13 hardcoded secrets found by other tools, confirming it should not be the sole tool used for security scanning. `KICS` was the most effective secrets scanner overall.


### 3.3 Tool Selection Guide & Recommendations

The choice of tool depends heavily on the specific use case and team structure.

| Use Case                       | Recommended Tool(s)        | Justification                                                                                             |
| :----------------------------- | :------------------------- | :-------------------------------------------------------------------------------------------------------- |
| **Developer Pre-Commit Hooks** | `tfsec`                    | Fastest execution time and developer-friendly output. Low false-positive rate avoids developer friction.    |
| **CI/CD Pull Request Gating**  | `Checkov` + `KICS`         | `Checkov` provides the most comprehensive policy coverage for Terraform. `KICS` adds essential coverage for Pulumi and Ansible. Running both provides defense-in-depth. |
| **Compliance & Auditing**      | `Terrascan`                | Its primary strength is mapping findings directly to compliance frameworks like CIS, PCI-DSS, and HIPAA. |
| **Multi-Framework Teams**      | `KICS`                     | The only tool in this lab that supports Terraform, Pulumi, and Ansible, providing a unified scanning experience. |
| **Security Team Deep Dives**   | `Checkov`                  | Its graph-based model allows for complex queries and understanding relationships between misconfigured resources. |

### 3.4 CI/CD Integration Strategy

A multi-layered scanning strategy provides the best security posture.

1.  **Pre-Commit (Developer Laptop):**
    - **Tool:** `tfsec`
    - **Action:** Run on every `git commit`.
    - **Goal:** Catch low-hanging fruit and obvious errors instantly. Provide immediate feedback to the developer before code is ever pushed.

2.  **Pull Request (CI Pipeline):**
    - **Tools:** `Checkov` and `KICS`.
    - **Action:** Run as automated checks on every pull request. Fail the build if any `CRITICAL` or `HIGH` severity issues are found.
    - **Goal:** Enforce security policies centrally and prevent insecure code from being merged into the main branch.

3.  **Post-Merge/Nightly (Staging Environment):**
    - **Tools:** `Terrascan` and custom `Conftest` policies.
    - **Action:** Run nightly against the `main` branch or a staging environment.
    - **Goal:** Perform deep compliance checks, audit for policy drift, and generate reports for security and compliance teams.

### 3.5 Lessons Learned

- **No Silver Bullet:** Relying on a single IaC scanner is insufficient. A combination of tools is necessary to achieve comprehensive coverage, as each has unique strengths and blind spots (e.g., Terrascan missing secrets).
- **Context is Key:** The "best" tool is context-dependent. A fast tool like `tfsec` is perfect for developers, while a comprehensive tool like `Checkov` is better for centralized CI enforcement.
- **KICS is a Strong Contender for Polyglot Environments:** For organizations that haven't standardized on a single IaC framework, KICS provides invaluable consistency by scanning Terraform, Pulumi, Ansible, and more with a single engine.
- **False Positives are a Real Concern:** While low in this lab, tools with broader rule sets can generate more noise. A good strategy involves starting with a baseline of high-confidence rules and gradually enabling more as the team matures.

### 3.6 Justification for Tool Choices and Strategy

The recommended CI/CD integration strategy is based on a "shift-left," defense-in-depth approach. The reasoning for each tool's placement in the pipeline is explained below.

1.  **`tfsec` in Pre-Commit:**
    - **Justification:** The primary goal at this stage is **speed and developer experience**. `tfsec` is the fastest tool (~5s) with the lowest false-positive rate. This provides immediate, high-confidence feedback without frustrating developers with slow checks or irrelevant warnings, encouraging adoption.

2.  **`Checkov` and `KICS` in Pull Request (CI):**
    - **Justification:** This stage is the main quality gate.
        - `Checkov` is chosen for its **comprehensive policy library** (78 findings), ensuring deep and broad coverage for Terraform, especially for complex IAM and network rules. It acts as the primary enforcement tool.
        - `KICS` is added for its **multi-framework support**. It is the only tool that can scan Pulumi and Ansible code, ensuring that no part of the IaC stack is left unscanned. Its strength in **secrets detection** (found 10 secrets vs. Terrascan's 0) provides a critical safety net that justifies its inclusion.
    - **Strategy:** Running both tools provides overlapping coverage and catches framework-specific issues, justifying a multi-tool approach for robust gating.

3.  **`Terrascan` in Post-Merge/Nightly:**
    - **Justification:** This stage focuses on **compliance and auditing**, not immediate feedback. `Terrascan` is selected here because its main strength is mapping findings to compliance standards (CIS, PCI-DSS).
    - **Strategy:** Running it nightly avoids slowing down the main development pipeline. Its higher false-positive rate is more manageable here, as results can be triaged by a dedicated security team rather than blocking developers. Its blind spot in secrets detection is compensated for by `KICS` earlier in the pipeline.

### 3.7 Top 5 Critical Findings (Terraform & Pulumi)

Across both Terraform and Pulumi, several critical vulnerabilities were consistently identified by the scanning tools.

1.  **Hardcoded Secrets in Code (CRITICAL)**
    - **Description:** AWS credentials, database passwords, and other secrets were hardcoded directly in `.tf` files and Pulumi's YAML manifest. This is a top IaC risk as it exposes secrets to anyone with code access.
    - **Detection:** Found by `tfsec`, `Checkov`, and `KICS`. KICS was particularly effective at finding secrets in both Pulumi and Ansible code.
    - **Remediation:** Use a dedicated secrets manager like HashiCorp Vault, AWS Secrets Manager, or the native secrets provider for the IaC tool (e.g., Pulumi Secrets, Ansible Vault).
      ```terraform
      # BAD: Hardcoded secret
      variable "db_password" {
        default = "my-super-secret-password-123!"
      }

      # GOOD: Secret injected from environment variable or secrets manager
      variable "db_password" {
        type      = string
        sensitive = true
      }
      ```

2.  **Publicly Exposed S3 Buckets (CRITICAL)**
    - **Description:** S3 buckets were configured with `acl = "public-read"`, making their contents accessible to the entire internet. This is a common cause of major data breaches.
    - **Detection:** Found by `tfsec`, `Checkov`, and `Terrascan`.
    - **Remediation:** Remove the public ACL and apply an `aws_s3_bucket_public_access_block` resource to enforce private access by default.
      ```terraform
      # GOOD: Enforce private access
      resource "aws_s3_bucket" "example" {
        # ... other bucket configuration
      }

      resource "aws_s3_bucket_public_access_block" "example" {
        bucket = aws_s3_bucket.example.id

        block_public_acls       = true
        block_public_policy     = true
        ignore_public_acls      = true
        restrict_public_buckets = true
      }
      ```

3.  **Overly Permissive Security Group Ingress (CRITICAL)**
    - **Description:** Security groups were configured to allow inbound traffic from `0.0.0.0/0` (any IP address) on sensitive ports like SSH (22) and RDP (3389). This exposes administrative interfaces to brute-force attacks.
    - **Detection:** Found by `tfsec`, `Checkov`, and `Terrascan`.
    - **Remediation:** Restrict ingress to known, trusted IP ranges. Avoid using `0.0.0.0/0` for anything other than public web traffic (ports 80, 443).
      ```terraform
      # BAD: Ingress open to the world on SSH port
      ingress {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }

      # GOOD: Ingress restricted to a specific IP
      ingress {
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["203.0.113.5/32"] # Your office/bastion IP
      }
      ```

4.  **Unencrypted Storage Resources (HIGH)**
    - **Description:** Resources like S3 buckets, RDS database instances, and EBS volumes were provisioned without server-side encryption enabled. This violates compliance standards and puts data at risk if physical storage is compromised.
    - **Detection:** Found by `tfsec` and `Checkov`.
    - **Remediation:** Explicitly enable server-side encryption for all storage resources. For S3, use `aws_s3_bucket_server_side_encryption_configuration`. For RDS and EBS, set the `encrypted` attribute to `true`.
      ```terraform
      # GOOD: RDS instance with encryption enabled
      resource "aws_db_instance" "default" {
        # ... other configuration
        storage_encrypted = true
      }
      ```

5.  **Overly Permissive IAM Policies (HIGH)**
    - **Description:** IAM roles and policies were created with wildcard permissions (e.g., `Action: "s3:*"` on `Resource: "*"`). This violates the principle of least privilege and can lead to catastrophic data loss or system compromise if the role is assumed by an attacker.
    - **Detection:** Found by `Checkov` and `tfsec`.
    - **Remediation:** Scope IAM policies to the minimum required actions and resources. Avoid wildcards (`*`) wherever possible.
      ```json
      // BAD: Overly permissive policy
      {
        "Action": "s3:*",
        "Effect": "Allow",
        "Resource": "*"
      }

      // GOOD: Least privilege policy
      {
        "Action": [
            "s3:GetObject",
            "s3:PutObject"
        ],
        "Effect": "Allow",
        "Resource": "arn:aws:s3:::my-specific-bucket/*"
      }
      ```