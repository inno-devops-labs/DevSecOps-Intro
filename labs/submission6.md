# Lab 6 — IaC Security Scanning and Comparative Analysis

## Task 1 — Terraform & Pulumi Security Scanning

### Terraform Scanning Results

I scanned the vulnerable Terraform code with three different tools: **tfsec**, **Checkov**, and **Terrascan**.

#### Summary of Terraform Findings

| Tool | Findings | Notes |
|------|----------:|------|
| tfsec | 53 | Strong Terraform-focused security checks, especially AWS misconfigurations |
| Checkov | 78 | Highest detection count, broad policy coverage, detailed compliance-style output |
| Terrascan | 22 | Smaller result set, more selective and policy-oriented |

#### Terraform Tool Observations

- **tfsec** was the fastest and easiest tool to use for Terraform-specific scanning.
- **Checkov** detected the highest number of issues and produced the most extensive result set.
- **Terrascan** found fewer issues, but its output was still useful for policy/compliance-oriented checks.
- The difference in counts shows that different tools use different rule sets, severities, and coverage models.

### Pulumi Scanning Results

I scanned the vulnerable Pulumi code with **KICS (Checkmarx)**.

#### Pulumi Findings Summary

- **Total findings:** 6
- **HIGH severity:** 2
- **MEDIUM severity:** 1
- **LOW severity:** 0

#### Pulumi Security Issues Identified by KICS

KICS successfully detected security issues in the Pulumi configuration, including:
- insecure cloud resource configuration
- missing encryption controls
- overly permissive access settings
- insecure defaults in infrastructure definitions

#### Evaluation of KICS for Pulumi

- KICS worked well for Pulumi YAML scanning.
- It provides useful HTML and JSON reports, which makes both manual review and automated analysis easier.
- Compared with Terraform tools, KICS found fewer issues, but it still identified meaningful high-risk misconfigurations.

### Terraform vs Pulumi Analysis

Terraform produced many more findings because it was scanned by three specialized tools, while Pulumi was scanned only with KICS. This does not necessarily mean that Pulumi is more secure; it mostly reflects the difference in tool ecosystem maturity and rule coverage.

---

## Task 2 — Ansible Security Analysis

I scanned the vulnerable Ansible playbooks with **KICS (Checkmarx)**.

### Ansible Findings Summary

- **Total findings:** 15
- **HIGH severity:** 9
- **MEDIUM severity:** 0
- **LOW severity:** 3

### Key Ansible Security Issues

KICS identified several important Ansible security problems, including:
- hardcoded secrets in playbooks and inventory
- insecure SSH settings
- overly permissive file permissions
- unsafe command execution patterns
- weak access control and privilege escalation risks

### Best Practice Violations

#### 1. Hardcoded secrets in playbooks and inventory
Placing passwords, API keys, or credentials directly in playbooks or inventory files creates a high risk of credential leakage through version control, logs, or accidental sharing.

**Security impact:** attackers can immediately reuse exposed secrets to access infrastructure or services.

#### 2. Insecure SSH configuration
Settings such as root login, password authentication, or disabled host key checking weaken remote access security.

**Security impact:** these settings increase the likelihood of brute-force attacks, credential theft, and man-in-the-middle attacks.

#### 3. Overly permissive file permissions
Using permissions such as `0777` or exposing private keys with weak permissions makes sensitive files accessible to unintended users.

**Security impact:** attackers or other users on the system may read or modify important files, including credentials and configuration.

### KICS Ansible Query Evaluation

KICS performs useful checks for Ansible in these areas:
- secrets management
- access control
- file permission hygiene
- risky command usage
- insecure configuration patterns

Its main strength is catching common operational security mistakes in automation code.

### Remediation Steps for Ansible Issues

- move secrets into **Ansible Vault** or external secret managers
- disable root login and password authentication for SSH
- enforce least privilege for sudo and service accounts
- replace risky shell/raw tasks with safer Ansible modules where possible
- set secure file permissions such as `0600` or `0640`
- avoid plaintext credentials in inventory files
- enable stricter validation and logging hygiene with `no_log: true` for sensitive tasks

---

## Task 3 — Comparative Tool Analysis & Security Insights

### Tool Comparison Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 | 78 | 22 | 21 (6 Pulumi + 15 Ansible) |
| **Scan Speed** | Fast | Medium | Medium | Medium |
| **False Positives** | Low | Medium | Low-Medium | Medium |
| **Report Quality** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Platform Support** | Terraform only | Multiple | Multiple | Multiple |
| **Output Formats** | JSON, text | JSON, CLI, SARIF, more | JSON, human | JSON, HTML, text |
| **CI/CD Integration** | Easy | Easy | Medium | Easy |
| **Unique Strengths** | Excellent Terraform-native checks | Broadest rule coverage | Policy/compliance orientation | Good multi-platform IaC coverage |

### Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|------------------|-------|---------|-----------|---------------|----------------|----------|
| **Encryption Issues** | Strong | Strong | Medium | Medium | N/A | Checkov |
| **Network Security** | Strong | Strong | Strong | Medium | Medium | tfsec |
| **Secrets Management** | Medium | Medium | Low | Medium | Strong | KICS (Ansible) |
| **IAM/Permissions** | Strong | Strong | Medium | Medium | Medium | Checkov |
| **Access Control** | Strong | Strong | Medium | Medium | Strong | Checkov / KICS |
| **Compliance/Best Practices** | Medium | Strong | Strong | Medium | Medium | Checkov / Terrascan |

### Top 5 Critical Findings

#### 1. Publicly accessible databases
Terraform findings showed RDS instances exposed publicly and security groups allowing broad network access.

**Risk:** direct exposure of databases to the internet can lead to unauthorized access, brute-force attempts, and data theft.

**Remediation example:**
```hcl
publicly_accessible = false
```

#### 2. Public S3 bucket configuration
Terraform included public bucket ACLs and missing public access blocking controls.

**Risk:** sensitive data may be exposed publicly or modified by unauthorized users.

**Remediation example:**
```hcl
acl = "private"
```

Add a public access block:
```hcl
block_public_acls       = true
block_public_policy     = true
ignore_public_acls      = true
restrict_public_buckets = true
```

#### 3. Hardcoded credentials and secrets
Secrets appeared in Terraform variables, Pulumi configuration, and Ansible playbooks/inventory.

**Risk:** credentials stored in code are easy to leak through Git history, logs, screenshots, or shared repositories.

**Remediation example:**
- use secret managers
- use environment variables
- use encrypted secret storage such as Ansible Vault

#### 4. Wildcard IAM permissions
Terraform IAM policies used wildcard permissions and overly broad resource scopes.

**Risk:** excessive permissions enable privilege escalation and lateral movement after compromise.

**Remediation example:**
```hcl
Action   = ["s3:GetObject", "s3:ListBucket"]
Resource = ["arn:aws:s3:::example-bucket", "arn:aws:s3:::example-bucket/*"]
```

#### 5. Insecure SSH and access-control settings in Ansible
Ansible automation included weak SSH practices and risky privilege configurations.

**Risk:** these issues can expose systems to brute-force attacks, privilege abuse, and remote compromise.

**Remediation example:**
- disable root SSH login
- disable password authentication
- require key-based access
- avoid unrestricted sudo rules

### Tool Selection Guide

#### When to use tfsec
Use **tfsec** when:
- the codebase is primarily Terraform
- fast feedback is needed in pull requests
- the team wants a simple, focused scanner for cloud misconfigurations

#### When to use Checkov
Use **Checkov** when:
- broad rule coverage is more important than scan simplicity
- multiple IaC and policy frameworks are present
- compliance and governance checks matter

#### When to use Terrascan
Use **Terrascan** when:
- policy-based control is important
- the team wants OPA-style compliance alignment
- lower-noise, policy-oriented results are preferred

#### When to use KICS
Use **KICS** when:
- multiple IaC technologies are used
- Pulumi and Ansible also need to be scanned
- HTML reports are useful for review and documentation

### Lessons Learned

- No single tool provides complete visibility across all IaC technologies.
- Tool choice strongly affects the number and type of findings.
- Checkov produced the highest number of findings, which suggests broader rule coverage.
- tfsec was the most convenient Terraform-focused tool.
- KICS is valuable because it can scan non-Terraform IaC such as Pulumi and Ansible.
- Different tools emphasize different categories: cloud misconfigurations, secrets, IAM, compliance, or automation hygiene.
- Running multiple tools together provides much better security coverage than relying on one scanner alone.

### CI/CD Integration Strategy

A practical multi-stage pipeline would be:

#### Stage 1 — Fast PR checks
- run **tfsec** on Terraform for quick feedback
- run **KICS** on Pulumi and Ansible for cross-platform baseline scanning

#### Stage 2 — Deeper validation before merge
- run **Checkov** for broader policy coverage
- run **Terrascan** for policy/compliance verification

#### Stage 3 — Scheduled full scans
- nightly or weekly scans with all tools
- archive JSON/HTML reports for trend comparison
- review recurring findings and policy gaps

#### Recommended workflow
1. Developers get fast scanner feedback in pull requests.
2. Broader scans run before merge to main.
3. Security/compliance jobs run on a schedule for full visibility.
4. Critical and high findings block merge.
5. Medium findings create tickets for remediation.

### Justification

My recommended strategy is to combine tools instead of choosing only one:

- **tfsec** for fast Terraform-native developer feedback
- **Checkov** for broad rule coverage and deeper policy checks
- **Terrascan** for compliance-oriented scanning
- **KICS** for Pulumi and Ansible support

This combination balances:
- speed
- coverage
- usability
- multi-platform support

In a real CI/CD environment, this layered approach reduces blind spots and improves the chance of catching both obvious and subtle IaC security issues before deployment.

---

## Final Conclusion

This lab demonstrated that IaC security scanning is most effective when multiple tools are used together. Terraform benefited from specialized scanners, while KICS provided valuable support for Pulumi and Ansible. The comparative analysis showed that each tool has different strengths, and an effective DevSecOps pipeline should combine fast developer-friendly checks with broader policy and compliance scanning.
