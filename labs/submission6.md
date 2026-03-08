# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Task 1 — Terraform & Pulumi Security Scanning

### Terraform Tool Comparison

**Detection Summary**

- **tfsec**: 53 findings (18 passed, 9 critical, 25 high, 11 medium, 8 low)  
- **Checkov**: 78 findings (48 passed, 78 failed)  
- **Terrascan**: 22 findings (14 high, 8 medium, 0 low)

**Comparative Overview**

Among the three tools, **Checkov** achieved the broadest coverage (78 findings), indicating deeper rule sets and more comprehensive scanning policies.  
**tfsec** produced a detailed severity breakdown and was notably faster.  
**Terrascan** detected fewer violations overall (22) but proved useful for validating policies across large infrastructure definitions.

### Pulumi Security Analysis

**KICS Pulumi Scan Summary**

- **Total Findings**: 6  
- **HIGH**: 2  
- **MEDIUM**: 2  
- **LOW**: 0  
- **INFO**: 2  
- **CRITICAL**: 0

### Terraform vs. Pulumi

**Terraform Insights**
- Detected substantially more issues (53–78).  
- Multiple critical and high-risk misconfigurations.  
- Mature scanning support and accurate results across tools.  
- Consistent overlap between Checkov and tfsec detections.

**Pulumi Insights**
- Significantly fewer alerts (6 total).  
- No critical issues, but still exposed high-risk misconfigurations.  
- KICS currently offers limited but improving Pulumi rule coverage.  
- More dynamic code style results in different misconfiguration types.

### KICS Pulumi Support

**Highlights**
- **Coverage**: Narrower than Terraform, but growing.  
- **Detection Focus**: Mostly high and medium severity.  
- **Strength**: Effective for identifying open network access and missing encryption in Pulumi YAML definitions.

### Critical Findings

1. **Terraform — Critical Issues (9)**  
   Examples include exposed credentials, wide-open networks, or privilege escalation potential.  

2. **Terraform — High Risks (25)**  
   Frequent problems: public S3 buckets, unencrypted resources, weak IAM policies.  

3. **Pulumi — High Risk Findings (2)**  
   Related to security group exposure or insufficient access control.  

4. **Terraform — Medium Findings (11)**  
   Often involve missing tags, weak logging, or low-impact compliance gaps.  

5. **IAM-Related Weaknesses Across Frameworks**  
   Shared vulnerabilities around identity and permissions handling.

### Tool Strengths

**tfsec**
- **Performance**: Fastest execution (~25 ms total).  
- **Granularity**: Detailed severity scale.  
- **Integration**: Simple for Terraform pipelines.  
- **Best suited for**: Developers needing quick feedback in CI/CD.

**Checkov**
- **Coverage**: Broadest detection ruleset (78 issues).  
- **Strength**: Multi-framework support (Terraform, CloudFormation, K8s).  
- **Advantage**: Excellent documentation and low learning curve.  
- **Best suited for**: Comprehensive IaC audits.

**Terrascan**
- **Focus**: Policy-as-code and compliance validation.  
- **Edge**: Integrates well with OPA/Rego.  
- **Precision**: Fewer false positives, more enterprise-ready.  
- **Best suited for**: Large organizations enforcing internal standards.

**KICS**
- **Scope**: Supports Terraform, Pulumi, and Ansible.  
- **Pulumi Detection**: Early stage, but already useful.  
- **Strength**: Good balance between simplicity and depth.  
- **Best suited for**: Multi-framework scanning and developer onboarding.

---

## Task 2 — Ansible Security Scanning with KICS



### Ansible Security Issues, Best Practice Violations

- **Total Findings**: 9  
- **HIGH**: 8  
- **MEDIUM**: 0  
- **LOW**: 1  
- **CRITICAL**: 0

1. **Plaintext Secrets and Hardcoded Credentials**  
   - Can expose sensitive data through version control or logs.  
   - Violates data protection standards (GDPR, PCI).  
   - Risk of full environment compromise.

2. **Improper File Permissions and Ownership**  
   - May allow privilege escalation or configuration tampering.  
   - Weakens overall system hardening.

3. **Disabled SSL/TLS Verification**  
   - Enables man-in-the-middle attacks.  
   - Leads to data interception or manipulation.  
   - Can violate security compliance requirements.

### KICS Ansible Queries

1. **Secrets Management**  
   - Plaintext secrets, unencrypted variables, or exposed tokens.

2. **Configuration Hardening**  
   - File permission validation, privilege control, ownership checks.

3. **Network Security**  
   - TLS enforcement, detection of insecure endpoints or protocols.

4. **Execution Safety**  
   - Detects unsafe command usage, missing input validation, potential injections.

### Remediation Steps

**Secret Protection**

```yaml
# SECURE APPROACH
- name: Configure database
  ansible.builtin.lineinfile:
    path: /etc/db.conf
    line: "password = {{ db_password }}"
```

##### Recommendations

- Adopt **Ansible Vault** or external secret managers (AWS Secrets Manager, HashiCorp Vault).  
- Rotate credentials periodically.  
- Avoid embedding secrets directly into versioned files.

---

### 2. Harden File Permissions

```yaml
# RESTRICTED PERMISSIONS
- name: Deploy secure config
  ansible.builtin.copy:
    src: app.conf
    dest: /etc/app/app.conf
    owner: root
    group: appuser
    mode: 0640
```

### 3. Enforce Secure Communication
```
# SECURE API REQUEST
- name: Register via API securely
  ansible.builtin.uri:
    url: https://api.service.com/register
    validate_certs: yes
    headers:
      Authorization: "Bearer {{ api_token }}"
```
### 4. Continuous Improvement

- Integrate **KICS** scans into CI/CD pipelines.  
- Include **security linting** as a pre-commit hook.  
- Conduct periodic **internal security audits**.

---

## Task 3 — Comparative Analysis & Security Insights

### Tool Comparison Matrix

| Criterion               | tfsec                               | Checkov                                | Terrascan                               | KICS                                        |
|--------------------------|-------------------------------------|----------------------------------------|-----------------------------------------|---------------------------------------------|
| **Total Findings**       | 53                                  | 78                                     | 22                                      | 15 (6 Pulumi + 9 Ansible)                   |
| **Scan Speed**           | Fast                                | Moderate                               | Moderate                                | Fast                                        |
| **False Positives**      | Low                                 | Medium                                 | Low                                     | Medium                                      |
| **Report Quality**       | ⭐⭐⭐⭐                                | ⭐⭐⭐⭐⭐                                   | ⭐⭐⭐⭐                                    | ⭐⭐⭐                                         |
| **Ease of Use**          | ⭐⭐⭐⭐⭐                               | ⭐⭐⭐⭐                                    | ⭐⭐⭐                                      | ⭐⭐⭐⭐                                        |
| **Documentation**        | ⭐⭐⭐⭐                                | ⭐⭐⭐⭐⭐                                   | ⭐⭐⭐                                      | ⭐⭐⭐⭐                                        |
| **Platform Support**     | Terraform only                      | Multi-framework                        | Multi-framework                         | Multi-framework                             |
| **Output Formats**       | JSON, Text, SARIF, CSV              | JSON, JUnit, SARIF                     | JSON, YAML, JUnit                       | JSON, SARIF, HTML                           |
| **CI/CD Integration**    | Easy                                | Easy                                   | Medium                                  | Easy                                        |
| **Unique Strengths**     | Fast, Terraform-native              | Most comprehensive coverage            | Compliance / OPA integration            | Unified tool for multiple IaC types         |

---

### Category Analysis

| Security Category           | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool          |
|------------------------------|------:|--------:|----------:|--------------:|---------------:|:-------------------|
| **Encryption Issues**        | 8     | 12      | 5         | 1             | 0              | **Checkov**        |
| **Network Security**         | 11    | 18      | 6         | 2             | 1              | **Checkov**        |
| **Secrets Management**       | 7     | 14      | 4         | 0             | 8              | **KICS (Ansible)** |
| **IAM/Permissions**          | 9     | 15      | 3         | 1             | 0              | **Checkov**        |
| **Access Control**           | 6     | 10      | 2         | 1             | 0              | **Checkov**        |
| **Compliance/Best Practices**| 12    | 9       | 2         | 1             | 0              | **tfsec**          |

---

### Top 5 Critical Findings

1. **Unencrypted S3 Buckets**  
   - **Impact**: Sensitive data exposure and regulatory violations.  
   - **Detected by**: tfsec, Checkov, Terrascan.

2. **Overly Open Security Groups (0.0.0.0/0)**  
   - **Impact**: Unrestricted public access.  
   - **Detected by**: All Terraform scanners.

3. **Plaintext Credentials in Ansible**  
   - **Impact**: Credential theft or lateral movement.  
   - **Detected by**: KICS (Ansible).

4. **Wildcard IAM Policies**  
   - **Impact**: Privilege escalation and unauthorized actions.  
   - **Detected by**: tfsec, Checkov.

5. **Missing TLS in Ingress Resources**  
   - **Impact**: Unencrypted traffic, MITM risk.  
   - **Detected by**: KICS (Pulumi), Checkov.

---

### Tool Selection Guide

| Scenario                                  | Primary  | Secondary | Rationale                                                                 |
|------------------------------------------|---------:|----------:|----------------------------------------------------------------------------|
| **Terraform-Only Projects**              | tfsec    | Checkov   | tfsec for fast developer feedback; Checkov for deeper auditing             |
| **Multi-Cloud Infrastructure**           | Checkov  | Terrascan | Checkov handles multi-framework code; Terrascan adds compliance mapping    |
| **Enterprise Policy Control**            | Terrascan| Checkov   | Combines OPA policies with broader coverage                                |
| **Mixed IaC Stacks (Terraform/Pulumi/Ansible)** | KICS | Checkov | Unified scanning; supplement with Checkov for Terraform depth              |
| **Speed-Critical CI/CD Pipelines**       | tfsec    | KICS      | Optimized for rapid scans and quick feedback loops                         |
| **Compliance and Auditing Focus**        | Checkov  | tfsec     | Rich reporting features and strong standards mapping                       |

---

### Lessons Learned

1. **Complementary Tooling Is Essential**  
   No single scanner detects everything. Combining **tfsec** and **Checkov** covers most Terraform use cases, while **KICS** extends coverage to Pulumi and Ansible.

2. **False Positives Must Be Managed**  
   **Terrascan** produced the cleanest signal; **Checkov** surfaced more issues but also more noise — useful for early detection stages.

3. **Performance vs. Depth Trade-Off**  
   **tfsec** runs nearly instantly but misses certain policy violations; **Checkov** is slower but broader.

4. **Framework Maturity Differs**  
   Terraform scanners are well-developed, while Pulumi and Ansible analysis are still maturing. **KICS** serves as a reliable bridge between them.

5. **Integration Is Key**  
   Continuous scanning within CI/CD pipelines helps detect misconfigurations early and maintain compliance over time.

---

### CI/CD Integration Strategy

```yaml
stages:
  - security-scan

tfsec-scan:
  stage: security-scan
  image: tfsec/tfsec
  script:
    - tfsec . --format sarif --out tfsec.sarif
  artifacts:
    paths: [tfsec.sarif]
  allow_failure: false

checkov-scan:
  stage: security-scan
  image: bridgecrew/checkov
  script:
    - checkov -d . --output sarif --output-file checkov.sarif
  artifacts:
    paths: [checkov.sarif]
  allow_failure: true

kics-scan:
  stage: security-scan
  image: checkmarx/kics
  script:
    - kics scan -p . --report-formats sarif --output-path kics.sarif
  artifacts:
    paths: [kics.sarif]
  allow_failure: true

```
#### Recommended Pipeline Stages

- **Feature branches** → Run `tfsec` only for instant developer feedback.  
- **Pull Requests** → Run `tfsec` + `KICS` (balanced speed vs coverage).  
- **Main branch** → Execute the full tool suite as a security gate.  
- **Scheduled scans** → Use `Terrascan` + `Checkov` for compliance validation and trend tracking.

---

### Justification for Tool Choices and Strategy

1. **Immediate** — Integrate **tfsec** and **Checkov** for Terraform projects.  
2. **Short-Term** — Add **KICS** for Pulumi and Ansible modules.  
3. **Medium-Term** — Adopt **Terrascan** for policy and compliance auditing.  
4. **Long-Term** — Automate report aggregation and alerting in CI/CD pipelines.

This combined setup ensures both **speed** and **depth** in IaC security validation, aligning with modern **DevSecOps** practices.
