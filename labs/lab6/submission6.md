## Task 1 — Security Scanning for Terraform & Pulumi (5 pts)

### 1.1 Prepare the Scanning Workspace

# Create a directory to store all analysis outputs
mkdir -p labs/lab6/analysis

<details>
<summary>Insecure IaC Code Layout</summary>

**Path:** `labs/lab6/vulnerable-iac/`

**Terraform** (`terraform/`): exposed S3 bucket, overly broad security groups (`0.0.0.0/0`), unencrypted RDS, wildcard IAM permissions, unsafe defaults.
**Pulumi** (`pulumi/`): `__main__.py`, `Pulumi.yaml`, `Pulumi-vulnerable.yaml` (public S3, unrestricted security groups, unencrypted databases).
**Ansible** (`ansible/`): embedded secrets, weak SSH settings, plaintext inventory.

> In total: 80+ deliberately insecure resources across multiple frameworks.

</details>

---

### 1.2 Analyze Terraform with tfsec

# Export JSON report
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src \
  --format json > labs/lab6/analysis/tfsec-results.json

# Export readable text report
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src \
  aquasec/tfsec:latest /src > labs/lab6/analysis/tfsec-report.txt

---

### 1.3 Analyze Terraform with Checkov

# JSON output
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  bridgecrew/checkov:latest \
  -d /tf --framework terraform \
  -o json > labs/lab6/analysis/checkov-terraform-results.json

# Concise text output
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf \
  bridgecrew/checkov:latest \
  -d /tf --framework terraform \
  --compact > labs/lab6/analysis/checkov-terraform-report.txt


---

### 1.4 Analyze Terraform with Terrascan

# JSON output
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac \
  tenable/terrascan:latest scan \
  -i terraform -d /iac \
  -o json > labs/lab6/analysis/terrascan-results.json

# Readable report
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac \
  tenable/terrascan:latest scan \
  -i terraform -d /iac \
  -o human > labs/lab6/analysis/terrascan-report.txt

---

### 1.5 Terraform Scan Review

The totals were combined with `jq` into `labs/lab6/analysis/terraform-comparison.txt`.

**Terraform Scanner Comparison (tfsec vs Checkov vs Terrascan)**

| Tool          | Findings                                                | Notes                                                |
| ------------- | ------------------------------------------------------- | ---------------------------------------------------- |
| **tfsec**     | **53** total — CRITICAL 9 • HIGH 25 • MEDIUM 11 • LOW 8 | Terraform-focused checks, straightforward severities |
| **Checkov**   | **78** failed checks                                    | Broadest ruleset, extensive policy support           |
| **Terrascan** | **22** policy violations — HIGH 14 • MEDIUM 8           | OPA-driven, compliance-oriented results              |

**Key Findings (Terraform):**

* **Network exposure**: `AVD-AWS-0107` (CRITICAL) — SG ingress `0.0.0.0/0` (`security_groups.tf:75–83`).
* **Unrestricted egress**: `AVD-AWS-0104` (CRITICAL) — egress `0.0.0.0/0` across several SGs.
* **Storage protection**: `AVD-AWS-0082` (CRITICAL) — public RDS without encryption (`database.tf:17`).
* **Public S3**: Terrascan `AC_AWS_0210/0496` (HIGH) — public ACL and no public access block (`main.tf:13`).
* **Disabled backups**: Terrascan `AC_AWS_0052` (HIGH) — RDS backups turned off.

---

### 1.6 Analyze Pulumi with KICS (Checkmarx)

# JSON + HTML reports
docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src \
  checkmarx/kics:latest \
  scan -p /src -o /src/kics-report --report-formats json,html

# Relocate reports into analysis directory
sudo mv labs/lab6/vulnerable-iac/pulumi/kics-report/results.json labs/lab6/analysis/kics-pulumi-results.json
sudo mv labs/lab6/vulnerable-iac/pulumi/kics-report/results.html labs/lab6/analysis/kics-pulumi-report.html

# Terminal summary
docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src \
  checkmarx/kics:latest \
  scan -p /src --minimal-ui > labs/lab6/analysis/kics-pulumi-report.txt 2>&1 || true

**Pulumi Security Review (KICS)**

| Metric             | Count |
| ------------------ | ----: |
| **Total findings** | **6** |
| - HIGH             |     2 |
| - MEDIUM           |     2 |
| - INFO             |     2 |

**Sample Issues (Pulumi YAML):**

* `b6a7e0ae-…` (HIGH): DynamoDB lacks `serverSideEncryption` — `Pulumi-vulnerable.yaml:205` → turn on SSE.
* `647de8aa-…` (MEDIUM): RDS has `publiclyAccessible: true` — `Pulumi-vulnerable.yaml:104` → switch to `false` and encrypt storage.

---

### Terraform vs Pulumi — Main Takeaways

* **Common ground:** both stacks contain at-rest encryption and public exposure weaknesses.
* **Differences:** Pulumi findings are more focused on resource properties (SSE, `publiclyAccessible`), while Terraform also exposes IAM and networking problems.
* **Conclusion:** Terraform’s declarative HCL makes insecure infrastructure defaults visible, whereas Pulumi requires deliberate handling of secrets and encryption settings.

---

### Remediation Highlights (Code-Level)

* **S3**: turn on versioning and SSE; deny public ACLs and public bucket policies.
* **RDS**: set `storage_encrypted = true`, `publicly_accessible = false`, enable backups and log exports.
* **Security Groups**: avoid `0.0.0.0/0`; narrow allowed CIDRs and ports.
* **Secrets**: eliminate hardcoded credentials; use AWS Secrets Manager or Pulumi config secrets.
* **Pipeline**: add Checkov and Terrascan to CI with severity-based enforcement.

---

## Task 2 — Ansible Security Analysis with KICS (2 pts)

### 2.1 Run KICS Against Ansible

# JSON + HTML reports
docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src \
  checkmarx/kics:latest \
  scan -p /src -o /src/kics-report --report-formats json,html

# Move generated reports
sudo mv labs/lab6/vulnerable-iac/ansible/kics-report/results.json labs/lab6/analysis/kics-ansible-results.json
sudo mv labs/lab6/vulnerable-iac/ansible/kics-report/results.html labs/lab6/analysis/kics-ansible-report.html
  
# CLI summary
docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src \
  checkmarx/kics:latest \
  scan -p /src --minimal-ui > labs/lab6/analysis/kics-ansible-report.txt 2>&1 || true
---

### 2.2 Ansible Security Review

`labs/lab6/analysis/ansible-analysis.txt` stores the aggregated counters produced with `jq`.

**Scan Overview**

| Metric               | Count |
| :------------------- | ----: |
| **Files scanned**    |     3 |
| **Lines scanned**    |   309 |
| **Queries executed** |   287 |
| **Total findings**   | **9** |
| • HIGH               |     8 |
| • MEDIUM             |     0 |
| • LOW                |     1 |
| • CRITICAL / INFO    |     0 |

**Most Important Detected Issues**

| Severity | Query ID / Rule Name                                        | File / Line                                                        | Category          | Description / Remediation                                                                                   |
| :------- | :---------------------------------------------------------- | :----------------------------------------------------------------- | :---------------- | :---------------------------------------------------------------------------------------------------------- |
| **HIGH** | `487f4be7-…` – **Passwords and Secrets – Generic Password** | `inventory.ini:5, 10, 18, 19`; `configure.yml:16`; `deploy.yml:12` | Secret Management | Hardcoded passwords/secrets → keep them in **Ansible Vault** or environment variables; remove from files.   |
| **HIGH** | `c4d3b58a-…` – **Passwords and Secrets – Password in URL**  | `deploy.yml:16, 72`                                                | Secret Management | Credentials embedded in URLs → replace with vaulted vars and secure lookups such as `lookup('env', 'VAR')`. |
| **LOW**  | `c05e2c20-…` – **Unpinned Package Version**                 | `deploy.yml:99`                                                    | Supply-Chain      | `state: latest` allows uncontrolled upgrades → lock versions or use `update_only: true`.                    |

**Examples of Best-Practice Violations and Their Impact**

1. **Plaintext secrets** in playbooks and inventory → immediate risk of credential disclosure.
2. **Credentials inside URLs** → visible in logs and process lists, increasing lateral movement risk.
3. **Unpinned packages** → unpredictable builds and possible supply-chain exposure.

**Recommended Remediation**

1. Protect secrets with **Ansible Vault** (`ansible-vault encrypt vars.yml`) and reference them through variables.
2. Apply `no_log: true` to sensitive tasks; replace inline URLs with vaulted credentials or `lookup('env', ...)`.
3. Lock package versions (`version: 1.2.3`), avoid `state: latest`, and favor native modules instead of `shell/command` whenever possible.

---

## Task 3 — Comparative Tool Review & Security Insights (3 pts)

### 3.1 Overall Tool Comparison

**Findings Summary**

| Tool               | Framework | Findings |
| :----------------- | :-------- | -------: |
| **tfsec**          | Terraform |   **53** |
| **Checkov**        | Terraform |   **78** |
| **Terrascan**      | Terraform |   **22** |
| **KICS (Pulumi)**  | Pulumi    |    **6** |
| **KICS (Ansible)** | Ansible   |    **9** |

*Source: `labs/lab6/analysis/tool-comparison.txt`*

**Tool Effectiveness Matrix**

| Criterion             |                     tfsec                     |               Checkov               |          Terrascan          |                   KICS                  |
| --------------------- | :-------------------------------------------: | :---------------------------------: | :-------------------------: | :-------------------------------------: |
| **Total Findings**    |                       53                      |                  78                 |              22             |          15 (Pulumi + Ansible)          |
| **Scan Speed**        |                     ⚡ Fast                    |                ⚡ Fast               |         🕐 Moderate         |               🕐 Moderate               |
| **False Positives**   |                      Low                      |                Medium               |            Medium           |                   Low                   |
| **Report Quality**    |                      ⭐⭐⭐⭐                     |                 ⭐⭐⭐⭐                |             ⭐⭐⭐             |                   ⭐⭐⭐                   |
| **Ease of Use**       |                      ⭐⭐⭐⭐                     |                 ⭐⭐⭐                 |              ⭐⭐             |                   ⭐⭐⭐                   |
| **Documentation**     |                      ⭐⭐⭐                      |                 ⭐⭐⭐⭐                |             ⭐⭐⭐             |                   ⭐⭐⭐⭐                  |
| **Platform Support**  |                 Terraform only                | Multi (Terraform, CFN, K8s, Docker) |    Multi (Terraform, K8s)   | Multi (Terraform, Pulumi, Ansible, K8s) |
| **Output Formats**    |               JSON, Text, SARIF               |           JSON, CLI, SARIF          |      JSON, YAML, Human      |            JSON, HTML, SARIF            |
| **CI/CD Integration** |                      Easy                     |                 Easy                |           Moderate          |                   Easy                  |
| **Key Strengths**     | Fast Terraform checks, clean severity mapping |  Broad multi-framework policy range | OPA-based compliance checks |     Strong Pulumi & Ansible support     |

---

### 3.2 Vulnerability Category Review

| Security Category               | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | 🏆 Best Tool            |
| ------------------------------- | :---: | :-----: | :-------: | :-----------: | :------------: | :---------------------- |
| **Encryption Issues**           |   ✅   |    ✅✅   |     ✅     |       ✅       |       N/A      | **Checkov**             |
| **Network Security**            |   ✅✅  |    ✅    |     ✅     |       ✅       |       N/A      | **tfsec**               |
| **Secrets Management**          |   ✅   |    ✅✅   |     ⚪     |       ✅       |       ✅✅       | **KICS (Ansible)**      |
| **IAM / Permissions**           |   ✅   |    ✅✅   |     ⚪     |       ⚪       |       N/A      | **Checkov**             |
| **Access Control**              |   ✅   |    ✅    |     ✅✅    |       ✅       |        ⚪       | **Terrascan**           |
| **Compliance / Best Practices** |   ⚪   |    ✅✅   |     ✅✅    |       ✅       |        ⚪       | **Terrascan / Checkov** |

**Legend:** ✅ = detects | ✅✅ = strong detection | ⚪ = limited coverage

---

### Top 5 Most Critical Findings (with Fix Suggestions)

| Tool               | Category           | Example Finding                                           | Risk                      | Recommended Fix                            |
| ------------------ | ------------------ | --------------------------------------------------------- | ------------------------- | ------------------------------------------ |
| **tfsec**          | Network Security   | `aws_security_group.database_exposed` (0.0.0.0/0 ingress) | Public database exposure  | Limit CIDRs and ports to trusted IPs only. |
| **Checkov**        | Data Protection    | `CKV_AWS_17` – Unencrypted RDS instance                   | Snapshot-based data theft | `storage_encrypted = true` + KMS key.      |
| **Terrascan**      | Compliance         | `AC_AWS_0052` – RDS backups disabled                      | Data loss on failure      | `backup_retention_period > 0`.             |
| **KICS (Pulumi)**  | Encryption         | DynamoDB missing SSE                                      | At-rest policy breach     | `serverSideEncryption: true`.              |
| **KICS (Ansible)** | Secrets Management | Hardcoded passwords in `inventory.ini`                    | Credential exposure       | Ansible Vault / secure secret lookups.     |

---

### Tool Selection Recommendations

| Use Case                               | Recommended Tool(s)  | Reasoning                                                     |
| :------------------------------------- | :------------------- | :------------------------------------------------------------ |
| **Rapid Terraform scanning in CI/CD**  | **tfsec**            | Lightweight, fast, and low false-positive rate.               |
| **Broad IaC policy validation**        | **Checkov**          | Extensive multi-framework support and very large ruleset.     |
| **Compliance / Governance checks**     | **Terrascan**        | OPA-backed policies aligned with PCI-DSS, HIPAA, and CIS.     |
| **Pulumi & Ansible security scanning** | **KICS (Checkmarx)** | Native Pulumi/Ansible support with consistent reporting.      |
| **Unified multi-framework scanning**   | **KICS + Checkov**   | Strong combined coverage and consistency across environments. |

---

### Lessons Learned

* No single scanner identifies every IaC risk; **using multiple tools together** provides the best coverage.
* **tfsec** is a strong choice for quick Terraform checks before commit.
* **Checkov** reports the highest number of issues, though it may require tuning to reduce false positives.
* **Terrascan** is especially effective in compliance-driven scenarios.
* **KICS** brings Pulumi and Ansible into the same security workflow.
* Overlapping results confirm genuine issues, while unique findings expose gaps in coverage.
