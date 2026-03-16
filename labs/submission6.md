# Lab 6 Submission — Infrastructure-as-Code Security: Scanning & Policy Enforcement

**Target:** Terraform, Pulumi, and Ansible code in `labs/lab6/vulnerable-iac/`  
**Tools used:** tfsec, Checkov, Terrascan (Terraform); KICS (Pulumi and Ansible).  
**Environment:** macOS, Docker (OrbStack), `jq` for parsing JSON outputs.

This document describes the steps I took to complete the lab, the commands I ran, the results I obtained, and my analysis. All scans were run manually from the repository root using the Docker commands from the lab instructions; summary statistics were produced with `jq` and written to `labs/lab6/analysis/`.

---

## What I Did — Step by Step

### Step 1: Prepare the analysis directory

I created the directory for all scan outputs:

```bash
cd /Users/pavorkmert/DevSecOps
mkdir -p labs/lab6/analysis
```

### Step 2: Scan Terraform with tfsec

I ran tfsec twice: once for JSON (for later parsing) and once for a human-readable report:

```bash
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src aquasec/tfsec:latest /src --format json > labs/lab6/analysis/tfsec-results.json
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/src aquasec/tfsec:latest /src > labs/lab6/analysis/tfsec-report.txt
```

The first run pulled the tfsec image; both completed successfully. tfsec reported multiple issues (e.g. public S3, open security groups, hardcoded credentials).

### Step 3: Scan Terraform with Checkov

I ran Checkov in JSON and compact text modes:

```bash
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf bridgecrew/checkov:latest -d /tf --framework terraform -o json > labs/lab6/analysis/checkov-terraform-results.json
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/tf bridgecrew/checkov:latest -d /tf --framework terraform --compact > labs/lab6/analysis/checkov-terraform-report.txt
```

Checkov attempted to fetch guidelines from the Bridgecrew API; the connection timed out, but the scan still completed using built-in policies and produced large JSON and text reports.

### Step 4: Scan Terraform with Terrascan

I ran Terrascan for JSON and human-readable output:

```bash
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac tenable/terrascan:latest scan -i terraform -d /iac -o json > labs/lab6/analysis/terrascan-results.json
docker run --rm -v "$(pwd)/labs/lab6/vulnerable-iac/terraform":/iac tenable/terrascan:latest scan -i terraform -d /iac -o human > labs/lab6/analysis/terrascan-report.txt
```

Terrascan showed warnings about fetching the AWS provider from the Terraform registry, but the scan finished and reported violations (e.g. security groups open to 0.0.0.0/0, IAM policies attached to users, RDP port exposed).

### Step 5: Build Terraform comparison summary

I used `jq` to extract finding counts from the three Terraform scan JSON files and wrote the summary to `terraform-comparison.txt`:

```bash
echo "=== Terraform Security Analysis ===" > labs/lab6/analysis/terraform-comparison.txt
tfsec_count=$(jq '.results | length' labs/lab6/analysis/tfsec-results.json 2>/dev/null || echo "0")
checkov_count=$(jq '.summary.failed' labs/lab6/analysis/checkov-terraform-results.json 2>/dev/null || echo "0")
terrascan_count=$(jq '.results.scan_summary.violated_policies' labs/lab6/analysis/terrascan-results.json 2>/dev/null || echo "0")
echo "tfsec findings: $tfsec_count" >> labs/lab6/analysis/terraform-comparison.txt
echo "Checkov findings: $checkov_count" >> labs/lab6/analysis/terraform-comparison.txt
echo "Terrascan findings: $terrascan_count" >> labs/lab6/analysis/terraform-comparison.txt
```

Result: **tfsec 53, Checkov 78, Terrascan 22** findings.

### Step 6: Scan Pulumi with KICS

I ran KICS on the Pulumi directory to generate JSON and HTML reports, then moved the reports into `analysis/` and ran KICS again with `--minimal-ui` to capture a text summary:

```bash
docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html
mv labs/lab6/vulnerable-iac/pulumi/kics-report/results.json labs/lab6/analysis/kics-pulumi-results.json
mv labs/lab6/vulnerable-iac/pulumi/kics-report/results.html labs/lab6/analysis/kics-pulumi-report.html
docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/pulumi":/src checkmarx/kics:latest scan -p /src --minimal-ui > labs/lab6/analysis/kics-pulumi-report.txt 2>&1
```

KICS detected Pulumi YAML and reported issues such as hardcoded database password, DynamoDB without encryption, and RDS publicly accessible.

### Step 7: Build Pulumi summary

I extracted severity and total counts from `kics-pulumi-results.json` and wrote them to `pulumi-analysis.txt`:

```bash
echo "=== Pulumi Security Analysis (KICS) ===" > labs/lab6/analysis/pulumi-analysis.txt
# ... jq for HIGH, MEDIUM, LOW, total_counter ...
```

Result: **6 total findings** (HIGH: 2, MEDIUM: 1, LOW: 0).

### Step 8: Scan Ansible with KICS

I ran KICS on the Ansible directory, moved the reports, and generated the text summary:

```bash
docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src checkmarx/kics:latest scan -p /src -o /src/kics-report --report-formats json,html
mv labs/lab6/vulnerable-iac/ansible/kics-report/results.json labs/lab6/analysis/kics-ansible-results.json
mv labs/lab6/vulnerable-iac/ansible/kics-report/results.html labs/lab6/analysis/kics-ansible-report.html
docker run -t --rm -v "$(pwd)/labs/lab6/vulnerable-iac/ansible":/src checkmarx/kics:latest scan -p /src --minimal-ui > labs/lab6/analysis/kics-ansible-report.txt 2>&1
```

KICS reported hardcoded passwords and secrets in `inventory.ini`, `deploy.yml`, and `configure.yml`, plus SSH and permission issues.

### Step 9: Build Ansible summary

I used `jq` on `kics-ansible-results.json` to write `ansible-analysis.txt`.

Result: **10 total findings** (HIGH: 9, MEDIUM: 0, LOW: 1).

### Step 10: Build overall tool comparison

I aggregated all counts into `tool-comparison.txt` using the same `jq` pattern so that a single file summarizes tfsec, Checkov, Terrascan, KICS Pulumi, and KICS Ansible results.

---

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1 Terraform tool comparison

The summary in `labs/lab6/analysis/terraform-comparison.txt` shows:

- **tfsec findings:** 53  
- **Checkov findings:** 78  
- **Terrascan findings:** 22  

Checkov reported the most findings, partly due to its broad policy set (including compliance and best-practice checks). tfsec and Terrascan focused more on core security issues. All three consistently flagged:

- **Storage:** Public S3 buckets, missing encryption, DynamoDB without encryption.  
- **Network:** Security groups allowing `0.0.0.0/0` for SSH, RDP, and database ports.  
- **Database:** RDS with `storage_encrypted = false`, `publicly_accessible = true`, no backup retention.  
- **IAM:** Wildcard actions/resources, over-privileged roles, credentials in outputs without `sensitive = true`.  
- **Defaults:** Insecure default values in `variables.tf`.

### 1.2 Pulumi (KICS) results

From `labs/lab6/analysis/pulumi-analysis.txt`:

- **Total Pulumi findings:** 6  
- **HIGH:** 2, **MEDIUM:** 1, **LOW:** 0  

KICS identified hardcoded secrets, RDS publicly accessible and unencrypted, DynamoDB without server-side encryption, and similar patterns to the Terraform code. KICS auto-detected Pulumi YAML and applied Pulumi-specific queries; the JSON and HTML reports made it easy to review by file and severity.

### 1.3 Terraform vs Pulumi

Terraform (HCL) and Pulumi (YAML/Python) showed similar vulnerability classes (open security groups, unencrypted storage, hardcoded credentials, wildcard IAM). Terraform benefited from three dedicated scanners (tfsec, Checkov, Terrascan); Pulumi was scanned with KICS, which has first-class Pulumi YAML support. In Pulumi, secrets in outputs or user data are easy to miss if not marked as `secret`, so tooling and code review both matter.

### 1.4 Critical findings (examples)

1. **Public S3 bucket without encryption** — Enable server-side encryption and block public access.  
2. **RDS publicly accessible and unencrypted** — Set `publicly_accessible = false`, `storage_encrypted = true`, restrict via VPC/security groups.  
3. **Security groups allowing 0.0.0.0/0** — Restrict to specific CIDRs or use a bastion/VPN.  
4. **Wildcard IAM policies** — Replace with least-privilege, scoped actions and resources.  
5. **Hardcoded credentials** — Use a secret manager (e.g. AWS Secrets Manager, Ansible Vault) and reference by name; avoid printing secrets in outputs or logs.

---

## Task 2 — Ansible Security Scanning with KICS

### 2.1 Ansible scan results

I scanned `labs/lab6/vulnerable-iac/ansible/` (deploy.yml, configure.yml, inventory.ini) with KICS. From `labs/lab6/analysis/ansible-analysis.txt`:

- **Total Ansible findings:** 10  
- **HIGH:** 9, **MEDIUM:** 0, **LOW:** 1  

KICS flagged hardcoded passwords and API keys in playbook variables and inventory, credentials in connection strings, and weak SSH/sudo settings.

### 2.2 Best practice violations and remediation

1. **Hardcoded passwords and secrets** — Impact: exposure via repo and logs; rotation and auditing are difficult. Remediation: use Ansible Vault or an external secret store and set `no_log: true` on sensitive tasks.  
2. **Missing `no_log` on sensitive operations** — Impact: secrets in task output and logs. Remediation: add `no_log: true` to any task that handles passwords or keys.  
3. **Insecure SSH and firewall** — Impact: root login, password auth, and open firewalls increase brute-force risk. Remediation: key-based auth, disable root login and password auth, restrict firewall to required sources and ports.

### 2.3 KICS Ansible coverage

KICS’ Ansible queries covered hardcoded secrets, insecure file modes, dangerous SSH/sudo configuration, and missing `no_log`. Using KICS for both Pulumi and Ansible kept the workflow consistent; for production I would add ansible-lint and possibly Conftest/OPA for custom rules.

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Tool comparison matrix

From `labs/lab6/analysis/tool-comparison.txt`:

| Tool        | Findings (this run)        |
|------------|----------------------------|
| tfsec      | 53 (Terraform)             |
| Checkov    | 78 (Terraform)             |
| Terrascan   | 22 (Terraform)             |
| KICS       | 6 (Pulumi) + 10 (Ansible)  |

| Criterion            | tfsec              | Checkov            | Terrascan          | KICS                    |
|----------------------|--------------------|--------------------|--------------------|-------------------------|
| **Total Findings**   | 53                 | 78                 | 22                 | 6 + 10                  |
| **Scan Speed**       | Fast               | Medium             | Medium             | Medium                  |
| **Report Quality**   | Text/JSON, concise | Rich JSON, SARIF   | Policy-focused     | JSON, HTML, console     |
| **Platform Support** | Terraform only     | Multiple           | Multiple           | Terraform, K8s, Pulumi, Ansible |
| **CI/CD**            | Easy               | Easy               | Easy–medium        | Easy (Docker)           |
| **Strengths**        | Low noise, fast    | Large rule set     | Compliance mapping | Pulumi & Ansible support|

### 3.2 Vulnerability categories

- **Encryption:** All tools flagged missing encryption on S3, RDS, DynamoDB; Checkov and Terrascan added compliance-style checks.  
- **Network:** All detected open security groups and public exposure.  
- **Secrets:** Checkov and tfsec in Terraform; KICS in Pulumi outputs and Ansible inventory/playbooks.  
- **IAM:** Terraform tools and KICS (Pulumi) flagged wildcard and over-privileged policies.

No single tool covered everything; combining them improved coverage.

### 3.3 Tool selection and CI/CD

Based on this lab I would:

- **Terraform:** tfsec for fast PR checks; Checkov in CI for broader coverage; Terrascan for compliance-focused or nightly runs.  
- **Pulumi & Ansible:** KICS as the main scanner in CI for both.  
- **Policy-as-code:** Conftest/OPA for org-specific rules (e.g. tagging, regions).

Pipeline: pre-commit or local runs with tfsec, Checkov, and KICS; CI on PRs with JSON/SARIF for the platform; scheduled or pre-release runs for Terrascan and OPA.

---

## Deliverables

- **labs/submission6.md** — This report (steps performed, results, analysis).  
- **labs/lab6/analysis/** — All scan outputs: tfsec (JSON, text), Checkov (JSON, text), Terrascan (JSON, text), KICS Pulumi (JSON, HTML, text), KICS Ansible (JSON, HTML, text), plus terraform-comparison.txt, pulumi-analysis.txt, ansible-analysis.txt, and tool-comparison.txt.

All numbers in this report match the files in `labs/lab6/analysis/` generated by the steps above.
