# Lab 6 — IaC Security Scanning & Comparative Analysis

## TL;DR

I scanned the vulnerable IaC code with the required tools and compared their coverage.  
Terraform produced the highest volume of findings with **Checkov (78)**, then **tfsec (53)**, then **Terrascan (22)**. Pulumi scanned with **KICS** produced **6** findings (**1 critical, 2 high, 1 medium, 2 info**). Ansible scanned with **KICS** produced **10** findings (**9 high, 1 low**). The strongest overall conclusion is that **Terraform has the most mature scanner ecosystem**, while **KICS is useful for Pulumi YAML and Ansible but has narrower practical coverage**, especially for Ansible operational misconfigurations.

---

## Scope and Evidence

This submission is based on the following generated artifacts in `labs/lab6/analysis/`:

- `tfsec-results.json`, `tfsec-report.txt`
- `checkov-terraform-results.json`, `checkov-terraform-report.txt`
- `terrascan-results.json`, `terrascan-report.txt`
- `kics-pulumi-results.json`, `kics-pulumi-report.txt`, `kics-pulumi-report.html`
- `kics-ansible-results.json`, `kics-ansible-report.txt`, `kics-ansible-report.html`
- `terraform-comparison.txt`, `pulumi-analysis.txt`, `ansible-analysis.txt`, `tool-comparison.txt`

The vulnerable code itself is located under:

- `labs/lab6/vulnerable-iac/terraform/`
- `labs/lab6/vulnerable-iac/pulumi/`
- `labs/lab6/vulnerable-iac/ansible/`

---

## 1. Terraform Tool Comparison

### 1.1 Summary Counts

| Tool | Findings |
|---|---:|
| tfsec | **53** |
| Checkov | **78** |
| Terrascan | **22** |

### 1.2 Main observation

The same Terraform codebase contains public S3 buckets, missing encryption, overly permissive security groups, publicly accessible RDS instances, excessive IAM permissions, and insecure defaults in variables. All three tools detected real issues, but they behaved differently:

- **tfsec** was the best for fast, Terraform-specific feedback and surfaced many high-signal issues with clear remediation text.
- **Checkov** had the broadest coverage and found the most findings, especially governance and best-practice checks.
- **Terrascan** produced fewer findings, but its output was focused and compliance-oriented.

### 1.3 What each Terraform tool did well

#### tfsec
Strengths:
- Excellent signal on **public exposure** and **encryption**.
- Very readable explanations with impact and remediation.
- Good at security-group, S3, DynamoDB, RDS, and IAM wildcard checks.

Examples from the report:
- `aws-rds-no-public-db-access` on `database.tf`
- `aws-ec2-no-public-ingress-sgr` on `security_groups.tf`
- `aws-s3-enable-bucket-encryption`
- `aws-iam-no-policy-wildcards`

Assessment:
- Best choice for **fast CI fail-fast checks** on Terraform pull requests.

#### Checkov
Strengths:
- Widest overall coverage.
- Strong on **IAM blast radius**, **governance**, and **operational hardening**.
- Catches many issues that tfsec does not emphasize as strongly, for example:
  - S3 lifecycle configuration
  - S3 event notifications
  - access logging
  - copy tags to snapshots
  - RDS query logging / monitoring
  - SSO vs direct IAM users
  - many IAM privilege-escalation / data-exfiltration patterns

Assessment:
- Best choice for **broad baseline coverage** and for organizations that want one tool across multiple IaC types.

#### Terrascan
Strengths:
- Leaner output than Checkov.
- Strong OPA/compliance style checks.
- Good focused detection of:
  - unrestricted specific ports (SSH / RDP / MySQL / PostgreSQL),
  - public S3 ACL + missing protection,
  - RDS encryption and public accessibility,
  - DynamoDB encryption / PITR,
  - IAM access key exposure.

Assessment:
- Best choice when the goal is **policy/compliance enforcement** and a smaller, easier-to-review report.

### 1.4 Terraform-specific findings that matter most

Most important classes repeatedly detected across tools:

1. **Public network exposure**
   - `security_groups.tf` allows `0.0.0.0/0`
   - SSH, RDP, MySQL, PostgreSQL open to the internet
   - RDS public access enabled in `database.tf`

2. **Missing encryption**
   - S3 bucket without encryption in `main.tf`
   - RDS storage encryption disabled in `database.tf`
   - DynamoDB encryption missing in `database.tf`

3. **Overly broad IAM**
   - wildcard `Action: "*"` and `Resource: "*"` in `iam.tf`
   - full service access and privilege-escalation paths

4. **Hardcoded credentials and unsafe defaults**
   - AWS credentials in `main.tf`
   - database password in `database.tf`
   - API key and weak defaults in `variables.tf`

---

## 2. Pulumi Security Analysis (KICS)

### 2.1 Summary Counts

| Severity | Count |
|---|---:|
| Critical | **1** |
| High | **2** |
| Medium | **1** |
| Low | **0** |
| Info | **2** |
| **Total** | **6** |

### 2.2 Findings detected by KICS

KICS detected these Pulumi findings from `Pulumi-vulnerable.yaml`:

1. **RDS DB Instance Publicly Accessible** — critical  
   - `Pulumi-vulnerable.yaml:104`

2. **DynamoDB Table Not Encrypted** — high  
   - `Pulumi-vulnerable.yaml:205`

3. **Passwords And Secrets - Generic Password** — high  
   - `Pulumi-vulnerable.yaml:16`

4. **EC2 Instance Monitoring Disabled** — medium  
   - `Pulumi-vulnerable.yaml:157`

5. **DynamoDB Table Point In Time Recovery Disabled** — info  
   - `Pulumi-vulnerable.yaml:213`

6. **EC2 Not EBS Optimized** — info  
   - `Pulumi-vulnerable.yaml:157`

### 2.3 Evaluation of KICS Pulumi support

KICS is clearly useful because it:
- auto-detected the Pulumi YAML manifest,
- produced JSON, HTML, and readable console output,
- identified real high-impact issues.

However, its practical coverage in this lab was **limited** compared with the known vulnerable code in `Pulumi-vulnerable.yaml`. The file contains much more than 6 issues, including:
- public S3 bucket,
- open security groups,
- wildcard IAM policy,
- excessive role permissions,
- secrets in user data,
- unencrypted EBS,
- secrets in outputs.

So my conclusion is:

- **KICS has real Pulumi support**
- but **its Pulumi query coverage is noticeably narrower than the Terraform scanner ecosystem**
- and **Pulumi scanning quality depends heavily on the exact representation** (here: YAML manifest, not the Python program)

### 2.4 KICS Pulumi strengths

What KICS did well on Pulumi:
- detected a **critical public RDS** issue,
- detected **hardcoded secret material**,
- detected **missing DynamoDB encryption**,
- produced a clean severity summary.

What KICS missed or under-reported in this lab:
- several network exposure issues present in the YAML,
- several IAM least-privilege violations,
- several broader design/security hygiene problems visible in the resource definitions.

---

## 3. Terraform vs. Pulumi Security Issues

### 3.1 Common issue patterns

Terraform and Pulumi both contain the same core vulnerability classes:

- public object storage,
- open security groups,
- publicly accessible databases,
- missing encryption,
- wildcard IAM permissions,
- hardcoded secrets.

So the security problem is not the framework itself; the problem is the **unsafe infrastructure design**.

### 3.2 Important difference in tooling maturity

The main difference in practice was **scanner maturity and coverage**:

- **Terraform** had three mature scanners and produced much richer coverage.
- **Pulumi** in this lab relied on **KICS against YAML**, which produced fewer findings.

This means:

- Terraform security scanning is easier to operationalize today with layered tooling.
- Pulumi can still be secured well, but it often needs a combination of:
  - KICS,
  - Pulumi-native policy tools (for example CrossGuard),
  - custom policy-as-code,
  - and in some teams even source-level scanning of the program code.

### 3.3 Declarative HCL vs programmatic / YAML Pulumi

#### Terraform (HCL)
Pros:
- Very mature static-analysis ecosystem.
- Resource schemas are predictable.
- Easier for scanners to parse consistently.

Cons:
- Still easy to encode insecure defaults and public access.
- Separate files can hide privilege relationships unless multiple tools are used.

#### Pulumi (YAML / programmatic approach)
Pros:
- Flexible and expressive.
- Easier to build abstractions and reuse logic.

Cons:
- Coverage depends more on the scanner’s parser and supported representation.
- Scanning YAML manifests is easier than scanning the full Python program.
- Some logic-level risks can sit outside the coverage of simple IaC scanners.

### 3.4 Conclusion

From a security-scanning point of view, **Terraform was easier to analyze comprehensively** in this lab.  
From an engineering point of view, Pulumi is still viable, but it benefits more from **policy enforcement inside the platform** plus **custom rules**.

---

## 4. Ansible Security Issues (KICS)

### 4.1 Summary Counts

| Severity | Count |
|---|---:|
| Critical | **0** |
| High | **9** |
| Medium | **0** |
| Low | **1** |
| Info | **0** |
| **Total** | **10** |

### 4.2 What KICS detected

KICS detected four query groups in the Ansible code:

1. **Passwords And Secrets - Generic Password** — 6 findings
2. **Passwords And Secrets - Generic Secret** — 1 finding
3. **Passwords And Secrets - Password in URL** — 2 findings
4. **Unpinned Package Version** — 1 finding

Examples:
- hardcoded secrets in `deploy.yml`
- plaintext credentials in `inventory.ini`
- admin password in `configure.yml`
- credentials embedded in Git URL / DB URL
- `state: latest` in `deploy.yml:99`

### 4.3 Best practice violations and security impact

Below are more than three important Ansible violations, with their impact.

#### Violation 1 — Hardcoded secrets in playbooks and inventory
Examples:
- `deploy.yml:12`
- `deploy.yml:16`
- `configure.yml:16`
- `inventory.ini:5`
- `inventory.ini:18-20`

Impact:
- Credentials leak through source control, CI logs, backups, screenshots, and local clones.
- Rotating them becomes difficult.
- The same credentials may be reused across environments.

Fix:
- Move secrets to **Ansible Vault**, environment-specific secret stores, or external secret managers.

#### Violation 2 — Credentials embedded in URLs
Examples:
- `deploy.yml:16`
- `deploy.yml:72`

Impact:
- URLs are commonly logged by shells, CI pipelines, proxies, and debugging tools.
- Secrets in URLs frequently leak into command history.

Fix:
- Use credential helpers, deploy keys, vault variables, or token injection at runtime.

#### Violation 3 — Non-deterministic package installation
Example:
- `deploy.yml:99` with `state: latest`

Impact:
- Builds become non-reproducible.
- Unexpected upstream package changes can break production or introduce unreviewed software.

Fix:
- Pin package versions and update them intentionally.

### 4.4 Important limitation of KICS on Ansible

This was one of the most important insights of the whole lab:

Although the Ansible code contains many additional security problems, the KICS results were dominated by **secrets detection** and did **not** capture a large part of the operational hardening issues present in the files, for example:

- `shell` instead of safer modules,
- `mode: '0777'`,
- SSH private key with `0644`,
- firewall disabled,
- weak SSH settings (`PermitRootLogin yes`, `PasswordAuthentication yes`),
- `StrictHostKeyChecking=no`,
- `raw` firewall flush,
- debug output exposing secrets.

So KICS is useful for **secret discovery** and some hygiene checks, but for Ansible I would not rely on it alone.  
A stronger pipeline would add:
- `ansible-lint`,
- custom OPA/Conftest policies,
- or Semgrep-style checks for command execution and insecure task patterns.

### 4.5 KICS Ansible query coverage evaluation

KICS performed well for:
- secrets management,
- plaintext credentials,
- password-in-URL patterns,
- deterministic package versioning hygiene.

KICS performed less well for:
- privilege-escalation patterns,
- shell/command misuse,
- file-permission hygiene,
- SSH hardening,
- network hardening,
- operational safety controls.

---

## 5. Comprehensive Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|---|---|---|---|---|
| **Total Findings** | 53 | 78 | 22 | 16 total (6 Pulumi + 10 Ansible) |
| **Primary Scope in this lab** | Terraform | Terraform | Terraform | Pulumi YAML + Ansible |
| **Scan Speed** | Fast | Medium | Fast/Medium | Medium |
| **False Positives** | Low | Medium | Low/Medium | Low on matched rules, but narrower coverage |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Platform Support** | Terraform-focused | Multi-framework | Multi-framework | Multi-framework |
| **Output Formats** | JSON, text, SARIF, etc. | JSON, CLI, SARIF, JUnit, CycloneDX, etc. | JSON, human | JSON, HTML, SARIF, console |
| **CI/CD Integration** | Easy | Easy/Medium | Medium | Easy/Medium |
| **Unique Strengths** | High-signal Terraform security checks and remediation text | Broadest policy catalog and governance coverage | OPA/compliance style policies with compact results | Unified scanning for Pulumi YAML and Ansible |

### 5.1 My ranking for this lab

1. **Checkov** — best overall Terraform coverage  
2. **tfsec** — best fast Terraform feedback loop  
3. **KICS** — necessary and useful for Pulumi/Ansible, but coverage was uneven  
4. **Terrascan** — solid compliance-focused supplement, but less complete than Checkov here

---

## 6. Vulnerability Category Analysis

> Counts below are **approximate grouped counts** based on rule names / descriptions from the generated reports.  
> They are intended for comparative analysis, not as an official taxonomy exported by the tools.

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|---|---:|---:|---:|---:|---:|---|
| **Encryption Issues** | 19 | 15 | 9 | 2 | 0 | tfsec / Checkov |
| **Network Security** | 17 | 19 | 6 | 1 | 0 | Checkov |
| **Secrets Management** | 0 | 3 | 1 | 1 | 9 | KICS (Ansible) |
| **IAM / Permissions** | 15 | 25 | 3 | 0 | 0 | Checkov |
| **Access Control** | 0 | 2 | 0 | 0 | 0 | Checkov |
| **Compliance / Best Practices** | 2 | 14 | 3 | 2 | 1 | Checkov |

### 6.1 Interpretation

- **tfsec** is strongest when the issue is a classic Terraform security misconfiguration.
- **Checkov** is strongest for **coverage breadth**, especially **IAM/governance/compliance**.
- **Terrascan** is a good targeted compliance supplement, not the most complete detector here.
- **KICS (Pulumi)** caught some high-value issues, but coverage was much narrower than the vulnerable code suggested.
- **KICS (Ansible)** was strongest for **secrets**, not for full Ansible hardening.

---

## 7. Top 5 Critical Findings with Remediation

### 7.1 Publicly accessible RDS instance

**Where**
- Terraform: `database.tf` (`publicly_accessible = true`)
- Pulumi: `Pulumi-vulnerable.yaml:104`

**Why this matters**
A public database dramatically increases attack surface and makes brute-force, exploitation, and credential-stuffing attacks much easier.

**Fix — Terraform**
```hcl
resource "aws_db_instance" "secure_db" {
  identifier              = "mydb-secure"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 7
  deletion_protection     = true
}
```

**Fix — Pulumi YAML**
```yaml
resources:
  secureDb:
    type: aws:rds:Instance
    properties:
      publiclyAccessible: false
      storageEncrypted: true
      backupRetentionPeriod: 7
      deletionProtection: true
```

---

### 7.2 Open security groups (`0.0.0.0/0`) for all / SSH / RDP / DB ports

**Where**
- `security_groups.tf`
- `Pulumi-vulnerable.yaml` security group resources

**Why this matters**
This exposes administrative and database surfaces directly to the internet and is one of the highest-risk IaC anti-patterns.

**Fix — Terraform**
```hcl
resource "aws_security_group" "app_sg" {
  name   = "app-sg"
  vpc_id = var.vpc_id

  ingress {
    description = "HTTPS from load balancer subnet only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.10.0/24"]
  }

  egress {
    description = "restricted outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.20.0/24"]
  }
}
```

---

### 7.3 Hardcoded cloud and application secrets

**Where**
- `main.tf` provider credentials
- `database.tf` password
- `variables.tf` default API key / weak defaults
- `Pulumi-vulnerable.yaml` variables
- `Pulumi.yaml` default secret values
- `deploy.yml`, `configure.yml`, `inventory.ini`

**Why this matters**
Secrets in source control are long-lived, easy to leak, and often reused across environments.

**Fix**
- Remove secrets from source code.
- Use:
  - AWS Secrets Manager / SSM Parameter Store for Terraform and Pulumi
  - Pulumi secret config
  - Ansible Vault for playbooks / inventory

**Fix — Ansible example**
```yaml
vars_files:
  - vault.yml

tasks:
  - name: Configure database credentials
    copy:
      dest: /etc/myapp/config.env
      content: "DB_PASSWORD={{ vault_db_password }}"
      mode: "0600"
    no_log: true
```

---

### 7.4 Wildcard IAM policies and privilege escalation paths

**Where**
- `iam.tf`
- `Pulumi-vulnerable.yaml` IAM policy sections

**Why this matters**
`Action = "*"` and `Resource = "*"` breaks least privilege and can enable lateral movement, destructive actions, and privilege escalation.

**Fix — Terraform**
```hcl
resource "aws_iam_policy" "read_only_bucket" {
  name = "read-only-bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["arn:aws:s3:::my-app-bucket/*"]
      }
    ]
  })
}
```

**Principle**
Scope permissions by:
- specific actions,
- specific resources,
- explicit deny where needed,
- role-based access instead of long-lived IAM users.

---

### 7.5 Insecure Ansible operational practices

**Where**
- `deploy.yml`
- `configure.yml`
- `inventory.ini`

Examples:
- `mode: '0777'`
- `shell:` for risky commands
- firewall disabled
- root login enabled
- `StrictHostKeyChecking=no`
- passwords in logs / task names / debug output

**Why this matters**
These patterns create credential leakage, command injection risk, privilege abuse, weak SSH posture, and non-auditable deployments.

**Fix — Ansible**
```yaml
- name: Install nginx safely
  apt:
    name: nginx=1.24.0-2
    state: present
    update_cache: yes

- name: Write secret config securely
  copy:
    dest: /etc/myapp/config.env
    content: "DB_PASSWORD={{ vault_db_password }}"
    owner: root
    group: root
    mode: "0600"
  no_log: true
```

---

## 8. Tool Selection Guide

### Use tfsec when:
- you want very fast Terraform-specific checks,
- you need clear remediation text,
- you want a lightweight PR gate.

### Use Checkov when:
- you want the broadest built-in policy coverage,
- you scan multiple IaC technologies,
- IAM/governance/compliance checks matter a lot.

### Use Terrascan when:
- you prefer OPA-style policy enforcement,
- compliance mapping matters,
- you want a focused supplemental scanner.

### Use KICS when:
- you need one tool across **Pulumi YAML** and **Ansible**,
- you want HTML output and unified reporting,
- secret detection matters.

### Best practical stack for this lab
- **Terraform:** `tfsec + Checkov` as the base, `Terrascan` as optional compliance supplement
- **Pulumi:** `KICS + Pulumi-native policy enforcement`
- **Ansible:** `KICS + ansible-lint + custom rules`

---

## 9. CI/CD Integration Strategy

A good real-world pipeline would be multi-stage.

### Stage 1 — Developer workstation / pre-commit
Run fast local checks:
- `tfsec` for Terraform
- lightweight secret scanning
- formatting / linting

Goal:
- fail early before code reaches CI.

### Stage 2 — Pull request checks
Run:
- `tfsec`
- `Checkov`
- `KICS` on Pulumi / Ansible
- optional secret scanning and policy tests

Policy:
- block merge on **critical/high** findings
- allow medium/low with tickets if justified

### Stage 3 — Main branch / nightly
Run broader and slower checks:
- Terrascan / OPA policy packs
- full artifact retention
- trend reporting and diff-based triage

### Stage 4 — Deployment guardrails
Use:
- policy-as-code,
- cloud-native preventive controls,
- drift detection,
- runtime configuration checks.

### Recommended decision rule
- **Critical / High**: fail pipeline
- **Medium**: warn or fail depending on environment
- **Low / Info**: backlog unless repeated / policy relevant

---

## 10. Lessons Learned

1. **Multiple tools are necessary.**  
   No single scanner covered everything well.

2. **Terraform security scanning is much more mature.**  
   The combination of tfsec + Checkov provided much deeper coverage than KICS on Pulumi YAML.

3. **KICS is useful but not sufficient by itself for Ansible.**  
   It was strongest on secrets, not on full operational hardening.

4. **Report volume is not equal to report quality.**  
   Checkov found the most issues, but tfsec often gave the cleanest high-signal remediation path.

5. **Framework coverage and representation matter.**  
   Pulumi YAML could be scanned, but the Python-based Pulumi program would still need additional controls.

6. **Security issues repeat across frameworks.**  
   Public exposure, weak IAM, missing encryption, and secrets in code are universal IaC failure modes.

---

## 11. Final Justification

My final recommendation for this lab’s tool strategy is:

- **Terraform:** Checkov + tfsec as the primary pair  
- **Pulumi:** KICS as baseline, but not the only control  
- **Ansible:** KICS only as a partial baseline; add ansible-lint and custom policy checks  
- **Compliance / policy overlays:** Terrascan or OPA/Conftest where organizational policy matters

This recommendation is justified by the actual outputs:
- Checkov found the most Terraform issues,
- tfsec provided strong actionable Terraform findings,
- Terrascan added a smaller compliance-oriented view,
- KICS was necessary for Pulumi and Ansible, but showed narrower detection coverage than the vulnerable code suggests.

Overall, the best DevSecOps approach is **layered scanning**, not single-tool dependence.
